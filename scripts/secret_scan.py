import os,pathlib,subprocess,sys,uuid,zipfile
root=pathlib.Path(__file__).resolve().parents[1]
env=os.environ.copy();env['GOCACHE']=str(root/'.cache/go-build');env['GOMODCACHE']=str(root/'.cache/go-mod');env['GOMAXPROCS']='2';env['GOFLAGS']='-p=2'
scan=root/'.cache'/('public-scan-'+uuid.uuid4().hex);scan.mkdir(parents=True)
with zipfile.ZipFile(root/'dist/nvuto-auth-0.1.0-source.zip') as archive:
 for name in archive.namelist():
  relative=pathlib.PurePosixPath(name)
  if relative.is_absolute() or '..' in relative.parts:raise SystemExit('Unsafe archive path')
 archive.extractall(scan)
command=['go','run','github.com/zricethezav/gitleaks/v8@v8.24.2','dir',str(scan),'--no-banner','--redact','--report-format','json','--report-path',str(root/'.cache/secret-scan.json')]
result=subprocess.run(command,cwd=root,env=env)
sys.exit(result.returncode)
