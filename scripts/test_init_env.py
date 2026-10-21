import importlib.util,pathlib,re,tempfile,unittest
spec=importlib.util.spec_from_file_location('init_env',pathlib.Path(__file__).with_name('init_env.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class ConfigurationCreation(unittest.TestCase):
 def test_independent_keys_matching_runtime_and_no_overwrite(self):
  with tempfile.TemporaryDirectory() as directory:
   path=pathlib.Path(directory)/'private.env';module.create(path)
   original=path.read_text();values=dict(line.split('=',1) for line in original.splitlines() if line and not line.startswith('#'))
   admin=values['POSTGRES_PASSWORD'];runtime=values['AUTH_DATABASE_PASSWORD'];key=values['AUTH_ENCRYPTION_KEYS'].split(':',1)[1]
   for value in [admin,runtime,key]:self.assertRegex(value,r'^[0-9a-f]{64}$')
   self.assertEqual(len({admin,runtime,key}),3)
   self.assertIn('auth_runtime:'+runtime+'@',values['DATABASE_URL'])
   with self.assertRaises(FileExistsError):module.create(path)
   self.assertEqual(path.read_text(),original)
   second=pathlib.Path(directory)/'second.env';module.create(second);self.assertNotEqual(second.read_text(),original)
if __name__=='__main__':unittest.main()
