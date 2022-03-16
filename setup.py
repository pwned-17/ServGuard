from setuptools import setup

config_location=[('/etc/ServGuard', ['servguard.conf'])]
setup(
    name='ServGuard',
    version='',
    packages=['servguard', 'servguard.lib', 'servguard.lib.IDS', 'servguard.lib.IDS.r2l_rules',
              'servguard.lib.IDS.r2l_rules.wireless', 'servguard.lib.WAF'],
    url='',
    data_files=config_location,
    license='',
    author='ajmal',
    author_email='shaikajmal.r2000@gmail.com',
    description=''
)
