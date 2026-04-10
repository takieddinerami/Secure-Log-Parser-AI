from setuptools import setup, find_packages

setup(
    name='secure-log-parser-ai',
    version='1.0.0',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    python_requires='>=3.9',
    install_requires=[
        # Core dependencies are standard library only
        # Optional dependencies in requirements.txt
    ],
    entry_points={
        'console_scripts': [
            'secure-log-parser-ai=secure_log_parser_ai.cli:main',
        ],
    },
)
