import json,os,pathlib,shutil,subprocess
root=pathlib.Path(__file__).resolve().parents[1]
env=os.environ.copy();env.setdefault('GOMAXPROCS','2');env.setdefault('GOFLAGS','-p=2');env['GOCACHE']=str(root/'.cache/go-build');env['GOMODCACHE']=str(root/'.cache/go-mod')
decoder=json.JSONDecoder();modules=[]
for directory in [root,root/'deploy/caddy']:
 raw=subprocess.check_output(['go','list','-deps','-json','./...'],cwd=directory,env=env,text=True,encoding="utf-8")
 while raw.strip():
  item,end=decoder.raw_decode(raw.lstrip());raw=raw.lstrip()[end:]
  module=item.get('Module')
  if module and not module.get('Main') and not any((m['Path'],m['Version'])==(module['Path'],module['Version']) for m in modules):modules.append(module)
destination=root/'third_party/licenses';destination.mkdir(parents=True,exist_ok=True)
lines=['# Third-party notices','','These unmodified license files accompany the application and HTTPS proxy dependencies in go.mod and deploy/caddy/go.mod. Dependency source is obtained through Go modules; the licenses below do not change its ownership.','']
for item in modules:
 module=pathlib.Path(item['Dir']);files=[p for p in module.iterdir() if p.is_file() and p.name.upper().startswith(('LICENSE','COPYING','NOTICE'))]
 if not files:raise SystemExit('No license found for '+item['Path'])
 for original in files:
  name=item['Path'].replace('/','__')+'@'+item['Version']+'__'+original.name
  shutil.copyfile(original,destination/name)
  lines.append('- '+item['Path']+' '+item['Version']+': [license](third_party/licenses/'+name+')')
goroot=pathlib.Path(subprocess.check_output(['go','env','GOROOT'],env=env,text=True,encoding="utf-8").strip())
shutil.copyfile(goroot/'LICENSE',destination/'Go-LICENSE')
lines.extend(['','The Go standard library and toolchain license is [included](third_party/licenses/Go-LICENSE).'])
(root/'THIRD_PARTY_NOTICES.md').write_text('\n'.join(lines)+'\n')
print('Recorded licenses for',len(modules),'modules and Go.')
