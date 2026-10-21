"""Create a deterministic source release from an explicit public allowlist."""
import hashlib,json,pathlib,zipfile
root=pathlib.Path(__file__).resolve().parents[1]
files=['main.go','go.mod','go.sum','README.md','LICENSE','NOTICE','THIRD_PARTY_NOTICES.md','SECURITY.md','CONTRIBUTING.md','CHANGELOG.md','.env.example','.gitignore','.gitattributes','.dockerignore','Dockerfile','compose.yaml','compose.production.yaml','openapi.json','.trivyignore']
for folder in ['internal/service','scripts','docs','examples','deploy','.github','third_party']:
 files.extend(str(p.relative_to(root)).replace('\\','/') for p in (root/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc')
files=sorted(set(files))
for name in files:
 if not (root/name).is_file():raise SystemExit('Missing release file: '+name)
 if (root/name).is_symlink() or not (root/name).resolve().is_relative_to(root.resolve()):raise SystemExit('Unsafe release path: '+name)
 if pathlib.Path(name).name.startswith('.env') and name!='.env.example':raise SystemExit('Private environment file in release')
 if any(part in ['reference','.local','.cache','.git'] for part in pathlib.Path(name).parts):raise SystemExit('Private path in release')
manifest=[{'path':name,'sha256':hashlib.sha256((root/name).read_bytes()).hexdigest()} for name in files]
dist=root/'dist';dist.mkdir(exist_ok=True)
path=dist/'nvuto-auth-0.1.0-source.zip'
with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as archive:
 for name in files:
  info=zipfile.ZipInfo('nvuto-auth-0.1.0/'+name,(2026,10,21,0,0,0));info.external_attr=(0o100755 if name.endswith('.sh') else 0o100644)<<16
  archive.writestr(info,(root/name).read_bytes(),compress_type=zipfile.ZIP_DEFLATED)
 archive.writestr('nvuto-auth-0.1.0/SOURCE-MANIFEST.json',json.dumps(manifest,indent=2)+'\n')
checksum=hashlib.sha256(path.read_bytes()).hexdigest()
(dist/'SHA256SUMS').write_text(checksum+'  '+path.name+'\n',encoding='utf-8',newline='\n')
print('Packaged',len(files),'public files:',path)
print('SHA-256:',checksum)
