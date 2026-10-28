#!/usr/bin/env python3
"""Domain-only Russian selective routing feed. Program MIT; data retains upstream terms."""
import argparse
import base64
import contextlib
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = '1.0.0'
ASSETS = ('ru-selective.srs', 'ru-selective.dat', 'ru-selective.json', 'manifest.json', 'SOURCE-NOTICES.txt')
MAX_AGE = 72*3600
MAX_ASSET_BYTES = 256*1024*1024
MAX_BUNDLE_BYTES = 768*1024*1024


class RuleError(Exception): pass


def sha(data): return hashlib.sha256(data).hexdigest()
def canonical(value): return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
def semantic_hash(rules): return sha(canonical(sorted(set(map(tuple, rules)))))
def stamp(now=None): return dt.datetime.fromtimestamp(now or time.time(), dt.timezone.utc).isoformat()
def read_json(path): return json.loads(Path(path).read_text('utf-8'))


def atomic(path, data):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.'+path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.chmod(tmp,0o640)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def save(path, value): atomic(path, canonical(value)+b'\n')


@contextlib.contextmanager
def lock(path, shared=False):
    # flock releases after crashes; never leaves a stale lock directory.
    import fcntl
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('r' if shared else 'a') as f:
        fcntl.flock(f, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        yield


def parse(data, default='domain_suffix'):
    out = set(); bad = 0
    types = {'full':'domain','domain':'domain_suffix','regexp':'domain_regex','regex':'domain_regex'}
    for raw in data.decode('utf-8-sig', errors='strict').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'): continue
        kind = default
        if ':' in line and line.split(':',1)[0] in types:
            prefix, line = line.split(':',1); kind = types[prefix]
        elif line.startswith('DOMAIN-SUFFIX,'): kind, line = 'domain_suffix', line.split(',',1)[1]
        elif line.startswith('DOMAIN,'): kind, line = 'domain', line.split(',',1)[1]
        if kind == 'domain_regex':
            if not line or len(line)>4096: raise RuleError('invalid regex length')
            out.add((kind,line)); continue  # Go RE2 is validated by both consumers.
        line=line.split('#',1)[0].strip().lower().rstrip('.')
        if not line: continue
        if line.startswith('*.'): line=line[2:]
        if line.startswith('.'): line=line[1:]
        try:
            ipaddress.ip_address(line); bad+=1; continue
        except ValueError: pass
        try:
            line=line.encode('idna').decode('ascii')
            labels=line.split('.')
            if len(line)>253 or any(not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?',x) for x in labels):
                raise ValueError('invalid domain')
            # TLD suffixes (.ua) are intentional upstream entries.
            out.add((kind,line))
        except (ValueError, UnicodeError): bad+=1
    return sorted(out), bad


def fetch(source):
    req=urllib.request.Request(source['url'], headers={'User-Agent':'ru-selective-rules/'+VERSION})
    with urllib.request.urlopen(req,timeout=90) as response:
        data=response.read(100*1024*1024+1)
        if len(data)>100*1024*1024: raise RuleError('source exceeds 100 MiB')
        return data, {'last_modified':response.headers.get('Last-Modified'), 'etag':response.headers.get('ETag'), 'final_url':response.url}


class Snapshots:
    def __init__(self,path): self.path=path
    def obtain(self,source,now,download=fetch,validate=None):
        path=self.path/(source['id']+'.json')
        old=read_json(path) if path.exists() else None
        try:
            data,headers=download(source)
            rules,bad=parse(data,source.get('default','domain_suffix'))
            if len(rules)<source.get('minimum',1): raise RuleError('source below minimum count')
            if bad>max(10,len(rules)*0.01): raise RuleError('source invalid rows exceed threshold')
            if old and len(rules)<len(old['rules'])*0.7:
                save(self.path/'quarantine'/(source['id']+'-'+str(int(now))+'.json'), {'count':len(rules),'sha256':sha(data),'reason':'count reduction >30%'})
                raise RuleError('source count reduction >30%; quarantined')
            # Do not overwrite the LKG snapshot until both consumers accept new content.
            if validate and (not old or rules!=list(map(tuple,old['rules']))):validate(rules)
            accepted={'id':source['id'],'url':source['url'],'accepted_at':now,'retrieved_at':stamp(now),'sha256':sha(data),'rules':[list(r) for r in rules],'count':len(rules),'rejected_rows':bad,'headers':headers,'license':source.get('license','Not established; upstream terms apply'),'stale':False}
            save(path,accepted)
            return accepted
        except (OSError,ValueError,RuleError) as exc:
            if old and 0<=now-old['accepted_at']<=MAX_AGE:
                return dict(old,stale=True,fetch_error=str(exc))
            raise RuleError(source['id']+': no valid snapshot <=72h: '+str(exc)) from exc


def varint(n):
    out=bytearray()
    while n>127: out.append((n&127)|128);n>>=7
    out.append(n);return bytes(out)


def field(tag,value): return varint(tag*8+2)+varint(len(value))+value


def encode_dat(rules):
    # Xray GeoSiteList.entry=1; GeoSite.country_code=1/domain=2;
    # Domain.type=1 (Regex=1, RootDomain=2, Full=3), value=2.
    body=bytearray(field(1,b'RU-SELECTIVE'))
    for kind,value in sorted(set(map(tuple,rules))):
        domain=b'\x08'+varint({'domain':3,'domain_suffix':2,'domain_regex':1}[kind])+field(2,value.encode())
        body.extend(field(2,domain))
    return field(1,bytes(body))


def decode_dat(blob):
    def vi(b,i):
        n=0;shift=0
        while True:
            v=b[i];i+=1;n|=(v&127)<<shift
            if v<128:return n,i
            shift+=7
    def fields(b):
        i=0
        while i<len(b):
            tag,i=vi(b,i)
            if tag&7==0: v,i=vi(b,i)
            elif tag&7==2: size,i=vi(b,i);v=b[i:i+size];i+=size
            else: raise RuleError('unexpected DAT wire type')
            yield tag>>3,v
    out=[]
    for _,site in fields(blob):
        for tag,domain in fields(site):
            if tag==1:
                if domain!=b'RU-SELECTIVE':raise RuleError('wrong DAT tag')
            if tag==2:
                d=dict(fields(domain));out.append(({1:'domain_regex',2:'domain_suffix',3:'domain'}[d[1]],d[2].decode()))
    return sorted(out)


def command(args,env=None):
    result=subprocess.run(args,capture_output=True,text=True,env=env)
    if result.returncode:raise RuleError(Path(args[0]).name+' failed: '+(result.stderr+result.stdout)[-4000:])
    return result.stdout.strip()


def validate_rules(rules,config):
    with tempfile.TemporaryDirectory() as tmp:
        p=Path(tmp);rule={}
        for k,v in rules:rule.setdefault(k,[]).append(v)
        save(p/'source.json',{'version':3,'rules':[rule]})
        atomic(p/'ru-selective.dat',encode_dat(rules))
        command([config['sing_box'],'rule-set','compile','--output',str(p/'source.srs'),str(p/'source.json')])
        validate_regex(p,rules,config)
        validate_xray(p,config)


def validate_regex(directory,rules,config):
    # Binary compilation and Xray -test do not instantiate regex matchers.
    # Inline sing-box routing check does, using the shared Go regexp dialect.
    expressions=[v for k,v in rules if k=='domain_regex']
    if not expressions:return
    path=Path(directory)/'regex-check.json'
    save(path,{'route':{'rules':[{'domain_regex':expressions,'action':'route','outbound':'direct'}]},'outbounds':[{'type':'direct','tag':'direct'}]})
    command([config['sing_box'],'check','-c',str(path)])


def validate_xray(directory,config):
    p=Path(directory)
    save(p/'xray.json',{'log':{'loglevel':'warning'},'inbounds':[],'outbounds':[{'protocol':'freedom','tag':'direct'}],'routing':{'rules':[{'type':'field','domain':['ext:ru-selective.dat:ru-selective'],'outboundTag':'direct'}]}})
    command([config['xray'],'run','-test','-config',str(p/'xray.json')],dict(os.environ,XRAY_LOCATION_ASSET=str(p)))


def check(directory,config):
    directory=Path(directory)
    for line in (directory/'SHA256SUMS').read_text().splitlines():
        digest,name=line.split('  ',1)
        if name not in ASSETS:raise RuleError('unexpected asset '+name)
        if sha((directory/name).read_bytes())!=digest:raise RuleError('hash mismatch: '+name)
    source=read_json(directory/'ru-selective.json')
    rules=sorted((k,v) for rule in source['rules'] for k,values in rule.items() for v in values)
    if decode_dat((directory/'ru-selective.dat').read_bytes())!=rules: raise RuleError('DAT semantic mismatch')
    command([config['sing_box'],'rule-set','decompile','--output',str(directory/'decompiled.tmp.json'),str(directory/'ru-selective.srs')])
    try:
        decoded=read_json(directory/'decompiled.tmp.json')
        # sing-box may normalize/sort lists, so compare field values as sets.
        decoded_rules=sorted((k,v) for rule in decoded['rules'] for k,values in rule.items() for v in values)
        if decoded_rules!=rules:raise RuleError('SRS semantic mismatch')
    finally: (directory/'decompiled.tmp.json').unlink(missing_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        p=Path(tmp);(p/'ru-selective.dat').write_bytes((directory/'ru-selective.dat').read_bytes())
        validate_regex(p,rules,config)
        validate_xray(p,config)
    return True


def build(config):
    state=Path(config['state']); now=time.time()
    snapshots=[Snapshots(state/'sources').obtain(s,now,validate=lambda r:validate_rules(r,config)) for s in config['sources']]
    rules=sorted(set((k,v) for s in snapshots for k,v in s['rules']))
    digest=semantic_hash(rules)
    save(state/'last-check.json',{'checked_at':stamp(now),'semantic_hash':digest,'sources':[{k:v for k,v in s.items() if k!='rules'} for s in snapshots]})
    current=read_json(state/'candidate.json') if (state/'candidate.json').exists() else None
    if current and current['semantic_hash']==digest:
        print('routing unchanged: '+digest);return
    root=state/'builds';root.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.build-',dir=root) as tmp:
        p=Path(tmp);rule={}
        for k,v in rules:rule.setdefault(k,[]).append(v)
        save(p/'ru-selective.json',{'version':3,'rules':[rule]})
        atomic(p/'ru-selective.dat',encode_dat(rules))
        command([config['sing_box'],'rule-set','compile','--output',str(p/'ru-selective.srs'),str(p/'ru-selective.json')])
        versions={'builder':VERSION,'dat_encoder':'Xray GeoSite protobuf wire v1','sing_box':command([config['sing_box'],'version']),'xray':command([config['xray'],'version'])}
        notices='Program: MIT. Data is NOT relicensed.\n'+ '\n'.join(s['id']+': '+s['url']+'\n'+s['license'] for s in config['sources'])+'\n'+(Path(__file__).parent/'THIRD-PARTY-NOTICES.txt').read_text('utf-8')
        atomic(p/'SOURCE-NOTICES.txt',notices.encode())
        # Detailed exceptions can contain local paths. Keep them in local health
        # diagnostics, never in public release metadata.
        save(p/'manifest.json',{'schema':1,'built_at':stamp(now),'semantic_hash':digest,'count':len(rules),'compilers':versions,'sources':[{k:v for k,v in s.items() if k not in ('rules','fetch_error')} for s in snapshots]})
        atomic(p/'SHA256SUMS',''.join(sha((p/name).read_bytes())+'  '+name+'\n' for name in ASSETS).encode())
        check(p,config)
        target=root/digest
        if not target.exists():
            os.chmod(p,0o750);os.replace(p,target)
        tag=dt.datetime.fromtimestamp(now,dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+digest[:16]
        save(state/'candidate.json',{'semantic_hash':digest,'tag':tag,'path':str(target),'built_at':stamp(now)})
    print('validated candidate '+digest)


class GitHub:
    def __init__(self,config):self.config=config;self.token=None;self.expires=0
    def request(self,method,url,data=None,auth=True,raw=False,headers=None):
        if url.startswith('/'):url='https://api.github.com'+url
        h={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'ru-selective-rules/'+VERSION}
        if auth:h['Authorization']='Bearer '+self.installation_token()
        if headers:h.update(headers)
        body=data if isinstance(data,bytes) else canonical(data) if data is not None else None
        if body is not None:h.setdefault('Content-Type','application/json')
        req=urllib.request.Request(url,data=body,method=method,headers=h)
        try:
            with urllib.request.build_opener(SafeRedirect()).open(req,timeout=120) as r:
                b=r.read();return b if raw else json.loads(b) if b else None
        except urllib.error.HTTPError as e:
            if e.code==404:return None
            raise RuleError('GitHub HTTP '+str(e.code)+' '+method+' '+url.split('?')[0]) from None
    def installation_token(self):
        if self.token and time.time()<self.expires-120:return self.token
        from cryptography.hazmat.primitives import hashes,serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        credential=Path(os.environ['CREDENTIALS_DIRECTORY'])/'github-app.pem'
        key=serialization.load_pem_private_key(credential.read_bytes(),password=None)
        enc=lambda b:base64.urlsafe_b64encode(b).rstrip(b'=')
        now=int(time.time());body=enc(canonical({'alg':'RS256','typ':'JWT'}))+b'.'+enc(canonical({'iat':now-60,'exp':now+540,'iss':str(self.config['app_id'])}))
        jwt=(body+b'.'+enc(key.sign(body,padding.PKCS1v15(),hashes.SHA256()))).decode()
        result=self.request('POST','/app/installations/'+str(self.config['installation_id'])+'/access_tokens',{'repositories':[self.config['repository'].split('/')[1]],'permissions':{'contents':'write'}},auth=False,headers={'Authorization':'Bearer '+jwt})
        self.token=result['token'];self.expires=dt.datetime.fromisoformat(result['expires_at'].replace('Z','+00:00')).timestamp();return self.token
    @property
    def base(self):return '/repos/'+self.config['repository']
    def get_release(self,tag=None,release_id=None):
        if release_id:return self.request('GET',self.base+'/releases/'+str(release_id))
        # Tag endpoint does not reliably find drafts. Paginate all releases for recovery.
        for page in range(1,1001):
            batch=self.request('GET',self.base+'/releases?per_page=100&page='+str(page))
            for r in batch:
                if r['tag_name']==tag:return r
            if len(batch)<100:return None
        raise RuleError('release pagination exhausted')
    def create_release(self,tag):return self.request('POST',self.base+'/releases',{'tag_name':tag,'name':tag,'draft':True,'prerelease':False,'body':'Domain-only selective rules. See manifest and source notices.'})
    def upload(self,release,name,data):return self.request('POST','https://uploads.github.com/repos/'+self.config['repository']+'/releases/'+str(release['id'])+'/assets?name='+urllib.parse.quote(name),data,headers={'Content-Type':'application/octet-stream'})
    def download(self,asset):return self.request('GET',self.base+'/releases/assets/'+str(asset['id']),raw=True,headers={'Accept':'application/octet-stream'})
    def publish(self,release_id):return self.request('PATCH',self.base+'/releases/'+str(release_id),{'draft':False,'make_latest':'true'})


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        redirected=super().redirect_request(req,fp,code,msg,headers,newurl)
        if urllib.parse.urlsplit(req.full_url).netloc!=urllib.parse.urlsplit(newurl).netloc:
            redirected.remove_header('Authorization')
        if urllib.parse.urlsplit(newurl).scheme!='https':raise RuleError('non-HTTPS redirect rejected')
        return redirected


@contextlib.contextmanager
def bundle_reader(directory):
    """Pin every directory component and forbid symlinks before opening any asset.

    Production is Linux. Windows fallback supports local verification only and
    rejects reparse points; it must never run the credentialed publisher.
    """
    directory=Path(os.path.abspath(directory))
    if os.name=='nt':
        def read(name,limit):
            path=directory/name
            for part in [path,*path.parents]:
                info=part.lstat()
                if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:raise RuleError('reparse point rejected')
            with path.open('rb') as f:
                if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):raise RuleError('nonregular asset')
                data=f.read(limit+1)
            if len(data)>limit:raise RuleError('asset exceeds size limit')
            return data
        yield read
        return
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
    fd=os.open(directory.anchor,flags)
    try:
        for component in directory.parts[1:]:
            next_fd=os.open(component,flags,dir_fd=fd)
            os.close(fd);fd=next_fd
        def read(name,limit):
            asset_fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            with os.fdopen(asset_fd,'rb') as f:
                info=os.fstat(f.fileno())
                if not stat.S_ISREG(info.st_mode):raise RuleError('nonregular asset')
                if info.st_size>limit:raise RuleError('asset exceeds size limit')
                data=f.read(limit+1)
            if len(data)>limit:raise RuleError('asset exceeds size limit')
            return data
        yield read
    finally:os.close(fd)


def load_bundle(directory):
    # These private immutable bytes are the only upload source. Never reopen
    # builder-owned files after validation or after obtaining credentials.
    with bundle_reader(directory) as read:
        bundle={'SHA256SUMS':read('SHA256SUMS',16384)}
        lines=bundle['SHA256SUMS'].decode('ascii').splitlines()
        listed=[line.split('  ',1)[1] for line in lines]
        if len(listed)!=len(ASSETS) or set(listed)!=set(ASSETS):raise RuleError('incomplete or duplicate bundle inventory')
        total=len(bundle['SHA256SUMS'])
        for line in lines:
            expected_hash,name=line.split('  ',1)
            if not re.fullmatch('[0-9a-f]{64}',expected_hash):raise RuleError('invalid asset checksum')
            data=read(name,min(MAX_ASSET_BYTES,MAX_BUNDLE_BYTES-total))
            total+=len(data)
            if sha(data)!=expected_hash:raise RuleError('local hash mismatch: '+name)
            bundle[name]=data
    return bundle


def release(api,directory,state_path,tag,digest,before_publish=None):
    bundle=load_bundle(directory)
    manifest=json.loads(bundle['manifest.json'])
    if manifest.get('semantic_hash')!=digest:raise RuleError('manifest semantic hash mismatch')
    expected={name:sha(data) for name,data in bundle.items()}
    previous=read_json(state_path) if Path(state_path).exists() else {}
    if previous.get('tag')!=tag:previous={'tag':tag,'semantic_hash':digest};save(state_path,previous)
    remote=api.get_release(release_id=previous.get('release_id'),tag=tag)
    if not remote:remote=api.create_release(tag)
    if remote['tag_name']!=tag:raise RuleError('recorded release tag mismatch')
    previous['release_id']=remote['id'];save(state_path,previous)
    # Refresh from ID on every run, including after lost upload/publish responses.
    remote=api.get_release(release_id=remote['id'])
    assets={a['name']:a for a in remote['assets']}
    if len(assets)!=len(remote['assets']):raise RuleError('duplicate remote asset names')
    if set(assets)-set(expected):raise RuleError('unexpected remote assets')
    for name,digest_expected in expected.items():
        asset=assets.get(name)
        if not asset:
            if not remote['draft']:raise RuleError('published release missing asset')
            asset=api.upload(remote,name,bundle[name])
        if sha(api.download(asset))!=digest_expected:raise RuleError('remote hash mismatch: '+name)
    # A release is made latest only after all bytes have been read back and verified.
    if remote['draft']:
        if before_publish:before_publish()
        api.publish(remote['id'])
    previous['published']=True;save(state_path,previous)


def publish(config):
    if os.name!='posix':raise RuleError('credentialed publishing requires Linux')
    state=Path(config['state']);pstate=Path(config['publisher_state'])
    candidate=read_json(state/'candidate.json')
    if not re.fullmatch('[0-9a-f]{64}',candidate['semantic_hash']):raise RuleError('invalid semantic hash')
    expected_path=state/'builds'/candidate['semantic_hash']
    if os.path.abspath(candidate['path'])!=os.path.abspath(expected_path):raise RuleError('candidate path outside expected build')
    # A healthy refresh must precede promotion; a failed latest build cannot publish stale output.
    def healthy():
        health=read_json(state/'last-check.json')
        if health['semantic_hash']!=candidate['semantic_hash']:raise RuleError('candidate does not match current source health')
        if {s['id'] for s in health['sources']}!={s['id'] for s in config['sources']}:raise RuleError('source health inventory mismatch')
        for source in health['sources']:
            if not 0<=time.time()-source['accepted_at']<=MAX_AGE:raise RuleError('expired accepted snapshot')
    healthy()
    old=read_json(pstate/'published.json') if (pstate/'published.json').exists() else {}
    if old.get('semantic_hash')==candidate['semantic_hash']:print('already published');return
    release(GitHub(config),expected_path,pstate/'release.json',candidate['tag'],candidate['semantic_hash'],before_publish=healthy)
    save(pstate/'published.json',candidate)
    print('published '+candidate['tag'])


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',default='/etc/ru-selective-rules/config.json');parser.add_argument('command',choices=['build','check','publish','status']);args=parser.parse_args()
    config=read_json(args.config)
    if args.command=='status':
        print(json.dumps({name:read_json(Path(root)/name) if (Path(root)/name).exists() else None for root,name in [(config['state'],'last-check.json'),(config['state'],'candidate.json'),(config['publisher_state'],'published.json')]},ensure_ascii=False,indent=2));return
    lockroot=Path(config['publisher_state'] if args.command=='publish' else config['state'])
    with lock(lockroot/'.lock'):
        if args.command=='build':
            # Remove health marker first: failure must prevent publication of a pending candidate.
            (Path(config['state'])/'last-check.json').unlink(missing_ok=True)
            build(config)
        elif args.command=='publish':
            with lock(Path(config['state'])/'.lock',shared=True):publish(config)
        else:check(read_json(Path(config['state'])/'candidate.json')['path'],config);print('verified')


if __name__=='__main__':
    try:main()
    except (RuleError,OSError,ValueError,subprocess.CalledProcessError) as exc:
        print('ERROR: '+str(exc),file=sys.stderr);sys.exit(1)
