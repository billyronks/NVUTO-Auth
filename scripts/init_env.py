"""Create a private Compose .env with independent secrets; never overwrite a file."""
import argparse, os, pathlib, secrets

def create(target):
 root=pathlib.Path(__file__).resolve().parents[1]
 admin,runtime,key=(secrets.token_hex(32) for _ in range(3))
 content=(root/'.env.example').read_text(encoding='utf-8')
 content=content.replace('REPLACE_WITH_RANDOM_HEX_MIGRATION_PASSWORD',admin)
 content=content.replace('REPLACE_WITH_DIFFERENT_RANDOM_HEX_RUNTIME_PASSWORD',runtime)
 content=content.replace('REPLACE_WITH_RUNTIME_PASSWORD',runtime)
 content=content.replace('REPLACE_WITH_64_RANDOM_HEX_CHARACTERS',key)
 descriptor=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(descriptor,'w',encoding='utf-8',newline='\n') as stream:stream.write(content)
 return target

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--output',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]/'.env')
 args=parser.parse_args()
 try:create(args.output)
 except FileExistsError:parser.exit(1,'Configuration already exists; left unchanged. Edit it or choose --output.\n')
 print('Private configuration created. Fill SMTP settings and BOOTSTRAP_EMAIL before starting. Secrets were not printed.')
