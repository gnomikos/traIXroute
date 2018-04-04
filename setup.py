from setuptools import setup
import os
from distutils.util import get_platform

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.rst')) as f:
    long_description = f.read()

def packages(lib):
    def dirs(*path):
        for location, _, _ in os.walk(os.path.join(*path)):
            yield location

    def modules(lib):
        return next(os.walk(lib))[1]

    r = []
    for module in modules(lib):
        for d in dirs(lib, module):
            r.append(d.replace('/', '.').replace('\\', '.')[len(lib) + 1:])
    return r

setup(
    name="traixroute",
    version="2.3",
    description='A tool that detects at which hop in a traceroute path an IXP fabric has been crossed.',
    long_description=long_description,
    package_dir={'': 'lib'},
    install_requires=['setuptools',
                      'cffi==1.7.0',
                      'cryptography==2.1.4',
                      'idna==2.1',
                      'pyasn1==0.1.9',
                      'pycparser==2.14',
                      'pyOpenSSL==17.4.0',
                      'pysubnettree==0.26',
                      'python-dateutil==2.5.3',
                      'pytz==2016.6.1',
                      'requests==2.18.4',
                      'ripe.atlas.cousteau==1.4',
                      'ripe.atlas.sagan==1.1.11',
                      'six==1.11.0',
                      'socketIO-client==0.7.0',
                      'ujson==1.35',
                      'websocket-client==0.37.0',
                      'fuzzywuzzy[speedup]==0.16.0',
                      'netaddr==0.7.19'
                      ],
    packages=packages('lib'),
    package_data={'': ['*.txt', '*.json',
                       '*.csv', 'config', 'RouteViews/routeviews']},
    author="Michalis Bamiedakis, Dimitris Mavrommatis and George Nomikos",
    author_email="gnomikos@ics.forth.gr",
    keywords="traIXroute Internet Exchange Points crossing traceroute ripe atlas",
    url="https://github.com/gnomikos/traIXroute",
    license='GNU General Public License v3 (GPLv3)',
    platforms=[get_platform(),],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Internet',
        'Intended Audience :: Telecommunications Industry',
        'Environment :: Console',
    ],

    entry_points={
        'console_scripts': [
            'traixroute = traixroute.application:run_traixroute',
            'scamper-install = traixroute.downloader.install_scamper:main',
        ],
    },
)
