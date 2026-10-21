import hashlib,json,os,pathlib,subprocess,uuid,zipfile
root=pathlib.Path(__file__).resolve().parents[1]
check=root/'.cache'/('clean-check-'+uuid.uuid4().hex);check.mkdir(parents=True)
with zipfile.ZipFile(root/'dist/nvuto-auth-0.1.0-source.zip') as archive:
 for name in archive.namelist():
  path=pathlib.PurePosixPath(name)
  if path.is_absolute() or '..' in path.parts:raise SystemExit('Unsafe archive member')
 archive.extractall(check)
source=check/'nvuto-auth-0.1.0';manifest=json.loads((source/'SOURCE-MANIFEST.json').read_text())
for required in ['Dockerfile','compose.yaml','compose.production.yaml','deploy/init-runtime.sh','deploy/Caddyfile','deploy/Dockerfile.caddy','deploy/Dockerfile.postgres','deploy/caddy/go.mod','deploy/caddy/go.sum','scripts/container_check.py','scripts/init_env.py','docs/SELF-HOSTING.md','docs/CONFIGURATION.md','docs/UPGRADING.md','docs/INTEGRATION.md','examples/product-app/main.go','examples/product-app/index.html','examples/product-app/app.js','examples/product-app/README.md']:
 if not (source/required).is_file():raise SystemExit('Missing deployment artifact: '+required)
for entry in manifest:
 name,want=entry['path'],entry['sha256']
 if hashlib.sha256((source/name).read_bytes()).hexdigest()!=want:raise SystemExit('Manifest mismatch: '+name)
 if any(part in ['reference','.local','.cache','.git'] for part in pathlib.Path(name).parts):raise SystemExit('Private data included')
env=os.environ.copy();env['GOCACHE']=str(root/'.cache/go-build');env['GOMODCACHE']=str(root/'.cache/go-mod');env['GOMAXPROCS']='2';env['GOFLAGS']='-p=2'
for args in [['go','test','./...'],['go','vet','./...'],['go','build','-trimpath','-o',str(check/'nvuto-auth.exe'),'.']]:subprocess.run(args,cwd=source,env=env,check=True)
print('Clean extracted release builds and tests independently; all source hashes match.')
