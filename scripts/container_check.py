"""Isolated Docker acceptance: real Caddy HTTPS and authenticated STARTTLS mail.
Requires Docker Compose >=2.24.4 and OpenSSL. Never uses a real SMTP account.
Only this run's Compose project and its volumes are removed in finally.
"""
import base64, hashlib, json, pathlib, queue, secrets, socket, socketserver, ssl, subprocess, threading, time, urllib.error, urllib.parse, urllib.request, uuid
root=pathlib.Path(__file__).resolve().parents[1]
run=root/'.local'/('containers-'+uuid.uuid4().hex);run.mkdir(parents=True,mode=0o700)
project='nvuto-check-'+uuid.uuid4().hex[:12]
def command(args,**kw):
 return subprocess.run([str(x) for x in args],check=True,**kw)
def output(args):
 return subprocess.check_output([str(x) for x in args],text=True).strip()
def freeport():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
port=freeport();public=f'https://localhost:{port}'
user='synthetic';password=secrets.token_hex(24);messages=queue.Queue()
command(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',run/'smtp.key','-out',run/'smtp.crt','-days','1','-subj','/CN=host.docker.internal','-addext','subjectAltName=DNS:host.docker.internal'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
(run/'smtp.crt').chmod(0o644)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(run/'smtp.crt',run/'smtp.key')
class SMTP(socketserver.BaseRequestHandler):
 def handle(self):
  conn=self.request;conn.settimeout(20);reader=conn.makefile('rb');secure=False;authenticated=False;recipient=''
  def reply(text):conn.sendall((text+'\r\n').encode())
  try:
   reply('220 synthetic SMTP')
   while True:
    line=reader.readline().decode().strip()
    if not line:return
    verb=line.split(' ',1)[0].upper()
    if verb=='EHLO':reply('250-synthetic\r\n250 AUTH PLAIN' if secure else '250-synthetic\r\n250 STARTTLS')
    elif verb=='STARTTLS':
     reply('220 begin TLS');reader.close();conn=context.wrap_socket(conn,server_side=True);reader=conn.makefile('rb');secure=True
    elif verb=='AUTH':
     expected=base64.b64encode(('\0'+user+'\0'+password).encode()).decode()
     authenticated=secure and line=='AUTH PLAIN '+expected
     reply('235 authenticated' if authenticated else '535 authentication failed')
    elif verb in ('MAIL','RCPT'):
     if not authenticated:reply('530 authentication required');continue
     if verb=='RCPT':recipient=line.split(':',1)[1].strip('<> ')
     reply('250 accepted')
    elif verb=='DATA':
     if not authenticated:reply('530 authentication required');continue
     reply('354 send data');body=[]
     while True:
      row=reader.readline()
      if not row: return
      if row==b'.\r\n':break
      body.append(row)
     messages.put((recipient,b''.join(body).decode()));reply('250 queued')
    elif verb=='QUIT':reply('221 bye');return
    elif verb=='RSET':reply('250 reset')
    else:reply('500 unsupported')
  except (OSError,ssl.SSLError):pass
  finally:reader.close();conn.close()
class Server(socketserver.ThreadingTCPServer):
 daemon_threads=True
server=Server(('0.0.0.0',0),SMTP);threading.Thread(target=server.serve_forever,daemon=True).start()
env={
 'POSTGRES_PASSWORD':secrets.token_hex(32),'AUTH_DATABASE_PASSWORD':secrets.token_hex(32),
 'AUTH_ACTIVE_KEY':'v1','AUTH_ENCRYPTION_KEYS':'v1:'+secrets.token_hex(32),'AUTH_DOMAIN':'localhost',
 'PUBLIC_URL':public,'REGISTRATION_MODE':'invite','SMTP_HOST':'host.docker.internal','SMTP_PORT':str(server.server_address[1]),
 'SMTP_USER':user,'SMTP_PASSWORD':password,'SMTP_CA_FILE':'/test/smtp.crt','MAIL_FROM':'auth@example.test',
 'BOOTSTRAP_TENANT':'acceptance','BOOTSTRAP_EMAIL':'owner@example.test','BOOTSTRAP_NAME':'Synthetic Owner'
}
envfile=run/'test.env';envfile.write_text(''.join(k+'='+v+'\n' for k,v in env.items()));envfile.chmod(0o600)
caddy=(root/'deploy/Caddyfile').read_text().replace('tls {','tls internal {')
(run/'Caddyfile').write_text(caddy)
# Generate JSON, which Compose accepts as YAML. The ports need a YAML !override tag.
override={'services':{}}
for name in ['auth','migrate','bootstrap']:
 override['services'][name]={'environment':{'PUBLIC_URL':public},'extra_hosts':['host.docker.internal:host-gateway'],'volumes':[str(run/'smtp.crt')+':/test/smtp.crt:ro']}
override['services']['edge']={'volumes':[str(run/'Caddyfile')+':/etc/caddy/Caddyfile:ro']}
(run/'override.json').write_text(json.dumps(override))
(run/'ports.yaml').write_text('services:\n  edge:\n    ports: !override ["127.0.0.1:'+str(port)+':443"]\n')
compose=['docker','compose','--progress','quiet','--project-name',project,'--env-file',envfile,'-f',root/'compose.yaml','-f',root/'compose.production.yaml','-f',run/'override.json','-f',run/'ports.yaml']
started=False
try:
 command(compose+['config','--quiet'])
 started=True
 command(compose+['up','-d','--build','auth','edge'])
 auth=output(compose+['ps','-q','auth']);edge=output(compose+['ps','-q','edge']);database=output(compose+['ps','-q','db'])
 supporting_images={name:json.loads(output(['docker','inspect',container]))[0]['Image'] for name,container in [('https_proxy',edge),('database',database)]}
 inspect=json.loads(output(['docker','inspect',auth]))[0]
 edge_info=json.loads(output(['docker','inspect',edge]))[0]
 assert edge_info['Config']['User']=='65532:65532'
 assert edge_info['HostConfig']['ReadonlyRootfs']
 assert 'ALL' in edge_info['HostConfig']['CapDrop']
 assert inspect['Config']['User']=='65532:65532'
 assert inspect['HostConfig']['ReadonlyRootfs']
 assert 'ALL' in inspect['HostConfig']['CapDrop']
 assert 'no-new-privileges:true' in inspect['HostConfig']['SecurityOpt']
 assert not inspect['HostConfig']['PortBindings']
 image=inspect['Image']
 command(['docker','tag',image,'nvuto-auth:acceptance'])
 for attempt in range(120):
  try:
   command(['docker','cp',edge+':/data/caddy/pki/authorities/local/root.crt',run/'https-ca.crt'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   break
  except subprocess.CalledProcessError:time.sleep(1)
 else:raise RuntimeError('HTTPS CA not ready')
 trusted=ssl.create_default_context(cafile=str(run/'https-ca.crt'))
 def request(want,path,body=None,access='',origin=None):
  data=None if body is None else json.dumps(body).encode()
  req=urllib.request.Request(public+path,data=data,headers={'Content-Type':'application/json','Origin':origin or public,**({'Authorization':'Bearer '+access} if access else {})})
  try:response=urllib.request.urlopen(req,context=trusted,timeout=10)
  except urllib.error.HTTPError as error:response=error
  with response:
   raw=response.read()
   assert response.status==want,(path,response.status,raw)
   assert response.headers.get('Strict-Transport-Security')=='max-age=31536000'
   assert response.headers.get('Cache-Control')=='no-store'
   assert response.headers.get('Set-Cookie') is None
   return json.loads(raw).get('data',{}) if raw.startswith(b'{') else raw
 for attempt in range(120):
  try:request(200,'/ready');break
  except (OSError,AssertionError):time.sleep(1)
 else:raise RuntimeError('HTTPS service did not become ready')
 request(200,'/account')
 try:urllib.request.urlopen(public+'/ready',timeout=5)
 except urllib.error.URLError:pass
 else:raise AssertionError('untrusted HTTPS certificate accepted')
 account_password=secrets.token_urlsafe(24)
 command(compose+['run','--rm','-T','bootstrap'],input=account_password+'\n',text=True)
 def mailtoken():
  recipient,body=messages.get(timeout=40)
  assert recipient=='owner@example.test'
  assert public+'/account#' in body
  return body.split('&token=',1)[1].split()[0]
 token=mailtoken()
 prefix='/api/v1/auth/'
 login={'tenant':'acceptance','email':'owner@example.test','password':account_password}
 request(401,prefix+'login',login)
 request(200,prefix+'resend-verification',{'tenant':'acceptance','email':'owner@example.test'})
 replacement_token=mailtoken()
 request(401,prefix+'verify-email',{'token':token})
 token=replacement_token
 request(200,prefix+'verify-email',{'token':token})
 request(401,prefix+'verify-email',{'token':token})
 request(403,prefix+'login',login,origin='https://attacker.example.test')
 session=request(200,prefix+'login',login);old=session['access_token']
 request(200,prefix+'me',access=old)
 request(200,prefix+'forgot-password',{'tenant':'acceptance','email':'owner@example.test'})
 token=mailtoken();replacement=secrets.token_urlsafe(24)
 request(200,prefix+'reset-password',{'token':token,'new_password':replacement})
 request(401,prefix+'me',access=old)
 request(401,prefix+'refresh',{'refresh_token':session['refresh_token']})
 login['password']=replacement;session=request(200,prefix+'login',login)
 session=request(200,prefix+'refresh',{'refresh_token':session['refresh_token']})
 request(200,prefix+'logout',{},session['access_token'])
 request(401,prefix+'me',access=session['access_token'])
 command(compose+['stop','-t','35','auth'])
 stopped=json.loads(output(['docker','inspect',auth]))[0]
 assert stopped['State']['ExitCode']==0,stopped['State']['ExitCode']
 evidence={'result':'passed','image_id':image,'supporting_image_ids':supporting_images,'non_root':True,'read_only':True,'cap_drop':'ALL','no_new_privileges':True,'auth_published_ports':False,'HTTPS':'Caddy, verified local CA, HSTS, origin rejection, no cookies, no-store','SMTP':'STARTTLS with verified local CA and AUTH PLAIN; actual worker delivers bootstrap verification and reset messages','lifecycle':'resend verification, invalidate prior link, verify, login, me, reset, revoke, refresh, logout','SIGTERM_exit_code':0,'external_provider_or_public_DNS':False,'docker':output(['docker','version','--format','{{.Server.Version}}'])}
 (run/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
 print(json.dumps(evidence,indent=2));print('Evidence:',run)
finally:
 if started:command(compose+['down','--volumes','--remove-orphans'])
 server.shutdown();server.server_close()
 envfile.unlink(missing_ok=True);(run/'smtp.key').unlink(missing_ok=True)
