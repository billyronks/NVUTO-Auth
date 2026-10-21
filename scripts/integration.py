"""Start a fresh private PostgreSQL cluster; never connects to an existing server."""
import json, os, pathlib, secrets, subprocess, sys, uuid, shutil, socket, urllib.request, time, signal
root=pathlib.Path(__file__).resolve().parents[1]
pg=pathlib.Path(os.environ.get('PG_BIN',r'C:\Program Files\PostgreSQL\18\bin' if os.name=='nt' else subprocess.check_output(['pg_config','--bindir'],text=True).strip()))
suffix='.exe' if os.name=='nt' else ''
run=root/'.local'/('acceptance-'+uuid.uuid4().hex)
run.mkdir(parents=True)
password=secrets.token_hex(32)
pw=run/'password.txt';pw.write_text(password)
with socket.socket() as sock:
 sock.bind(('127.0.0.1',0));port=str(sock.getsockname()[1])
def command(args,**kw):
 if str(args[0])=='go' and 'test' in args:
  result=subprocess.run([str(x) for x in args],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8',**kw)
  with (run/'test-output.log').open('a',encoding='utf-8') as evidence:evidence.write(result.stdout)
  print(result.stdout,flush=True)
  result.check_returncode()
  return result
 result=subprocess.run([str(x) for x in args],check=True,**kw)
 return result
command([pg/('initdb'+suffix),'-D',run/'data','-U','nvuto_test','--auth=scram-sha-256','--pwfile',pw,'--encoding=UTF8','--locale=C'],stdout=subprocess.DEVNULL)
env=os.environ.copy();env.setdefault('GOMAXPROCS','2');env.setdefault('GOFLAGS','-p=2');env['PGPASSWORD']=password
env['GOCACHE']=str(root/'.cache/go-build');env['GOMODCACHE']=str(root/'.cache/go-mod')
socket_option='' if os.name=='nt' else ' -c unix_socket_directories='
command([pg/('pg_ctl'+suffix),'-D',run/'data','-l',run/'postgres.log','-o',f'-h 127.0.0.1 -p {port}'+socket_option,'-w','start'],stdout=subprocess.DEVNULL)
try:
 command([pg/('createdb'+suffix),'-h','127.0.0.1','-p',port,'-U','nvuto_test','auth_acceptance'],env=env)
 runtime_password=secrets.token_hex(32)
 sql="CREATE ROLE auth_runtime LOGIN PASSWORD '"+runtime_password+"';"
 command([pg/('psql'+suffix),'-h','127.0.0.1','-p',port,'-U','nvuto_test','-d','auth_acceptance','-v','ON_ERROR_STOP=1','-c',sql],env=env,stdout=subprocess.DEVNULL)
 env['AUTH_TEST_ADMIN_URL']=f'postgres://nvuto_test:{password}@127.0.0.1:{port}/auth_acceptance?sslmode=disable'
 env['AUTH_TEST_DATABASE_URL']=f'postgres://auth_runtime:{runtime_password}@127.0.0.1:{port}/auth_acceptance?sslmode=disable'
 env['AUTH_ISOLATED_TEST']='1'
 (run/'environment.txt').write_text(subprocess.check_output(['go','version'],cwd=root,env=env,text=True)+subprocess.check_output([str(pg/('postgres'+suffix)),'--version'],text=True))
 race=['-race'] if os.environ.get('AUTH_TEST_RACE')=='1' else []
 command(['go','test',*race,'-p','2','-tags=integration','-count=1','-v','./internal/service'],cwd=root,env=env)
 # Exercise the actual command-line migration and running HTTP binary.
 command(['go','build','-o',root/'.cache/nvuto-auth.exe','.'],cwd=root,env=env)
 env.update(DATABASE_URL=env['AUTH_TEST_ADMIN_URL'],PUBLIC_URL='http://127.0.0.1:8081',AUTH_ACTIVE_KEY='v2',AUTH_ENCRYPTION_KEYS='v1:'+'78'*32+',v2:'+'79'*32,SMTP_HOST='127.0.0.1',SMTP_PORT='1',MAIL_FROM='auth@example.test',RUNTIME_DATABASE_ROLE='auth_runtime')
 command([root/'.cache/nvuto-auth.exe','migrate'],cwd=root,env=env)
 env['DATABASE_URL']=env['AUTH_TEST_DATABASE_URL']
 with socket.socket() as sock:
  sock.bind(('127.0.0.1',0));http_port=sock.getsockname()[1]
 env['LISTEN_ADDR']=f'127.0.0.1:{http_port}'
 env['PUBLIC_URL']=f'http://127.0.0.1:{http_port}'
 env['REGISTRATION_MODE']='public' # Synthetic example fixture in this isolated database only.
 server=subprocess.Popen([str(root/'.cache/nvuto-auth.exe'),'serve'],cwd=root,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 try:
  for attempt in range(100):
   if server.poll() is not None:raise RuntimeError('Service startup failed: '+server.stderr.read().decode())
   try:
    with urllib.request.urlopen(env['PUBLIC_URL']+'/ready',timeout=1) as response:
     assert response.status==200
    break
   except (OSError,urllib.error.URLError):time.sleep(0.1)
  else:raise RuntimeError('HTTP readiness timed out')
  with urllib.request.urlopen(env['PUBLIC_URL']+'/account') as response:
   assert "frame-ancestors 'none'" in response.headers['Content-Security-Policy']
   assert b'NVUTO Auth' in response.read()
  print('Native binary migration, restricted-role startup, readiness and browser smoke passed.')
  import example_smoke
  example_smoke.run(root,env,pg,port,command,run)
  (run/'native-smoke.json').write_text(json.dumps({'migration':'passed','runtime_role':'restricted','readiness':'passed','browser_headers':'passed','graceful_SIGTERM':'Linux CI gate' if os.name=='nt' else 'exercised'},indent=2))
 finally:
  if os.name=='nt':
   server.terminate()
   print('Windows process stopped; graceful SIGTERM is a Linux CI gate.')
  else:server.send_signal(signal.SIGTERM)
  code=server.wait(timeout=35)
  if os.name!='nt' and code!=0:raise RuntimeError('SIGTERM shutdown failed: '+str(code))
 # Backup/restore into a second isolated database, preserving encrypted factor records.
 command([pg/('pg_dump'+suffix),'-h','127.0.0.1','-p',port,'-U','nvuto_test','-d','auth_acceptance','-Fc','-f',run/'backup.dump'],env=env)
 command([pg/('createdb'+suffix),'-h','127.0.0.1','-p',port,'-U','nvuto_test','auth_restored'],env=env)
 command([pg/('pg_restore'+suffix),'-h','127.0.0.1','-p',port,'-U','nvuto_test','-d','auth_restored','--exit-on-error',run/'backup.dump'],env=env)
 env['AUTH_TEST_DATABASE_URL']=env['AUTH_TEST_DATABASE_URL'].replace('/auth_acceptance?', '/auth_restored?')
 command(['go','test','-p','2','-tags=restore','-run=TestRestoredRecords','-count=1','-v','./internal/service'],cwd=root,env=env)
 print('Backup and restore completed and encrypted factors verified in isolated databases.')
finally:
 command([pg/('pg_ctl'+suffix),'-D',run/'data','-m','fast','-w','stop'],stdout=subprocess.DEVNULL)
 pw.unlink(missing_ok=True)
 print('Private PostgreSQL cluster stopped. Evidence:',run)
