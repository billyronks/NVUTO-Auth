import os, pathlib, subprocess, sys
root=pathlib.Path(__file__).resolve().parents[1]
env=os.environ.copy();env.setdefault('GOMAXPROCS','2');env.setdefault('GOFLAGS','-p=2')
env['GOCACHE']=str(root/'.cache/go-build')
env['GOMODCACHE']=str(root/'.cache/go-mod')
subprocess.run([sys.executable,'-m','unittest','discover','-s','scripts','-p','test_*.py'],cwd=root,check=True)
for args in [['gofmt','-w','main.go','internal/service','examples','deploy/caddy'],['go','mod','tidy'],['go','test','-p','2','./...'],['go','vet','./...'],['go','build','-o','.cache/nvuto-auth.exe','.']]:
 print('Running:', ' '.join(args), flush=True)
 result=subprocess.run(args,cwd=root,env=env)
 if result.returncode: sys.exit(result.returncode)

import json,re
contract=json.loads((root/'openapi.json').read_text())
source=(root/'internal/service/service.go').read_text()
actual=set(re.findall(r'"(GET|POST|DELETE|PUT|PATCH) (/api/v1/auth[^"]+)"',source))
documented={(method.upper(),path) for path,operations in contract['paths'].items() if path.startswith('/api/v1/auth') for method in operations}
if actual!=documented:raise SystemExit('API contract mismatch: '+str(actual^documented))
print('API route contract matches:',len(actual),'operations')

for method,path in documented:
 operation=contract['paths'][path][method.lower()]
 if 'requestBody' in operation:
  expected=set(operation['requestBody']['content']['application/json']['schema']['properties'])
  pattern=method+' '+path
  match=re.search(re.escape('"'+pattern+'"')+r'\s*:\s*"([^"]*)"',source)
  if not match or set(match.group(1).split())!=expected:raise SystemExit('Request schema mismatch: '+pattern)
print('API request field contracts match')
