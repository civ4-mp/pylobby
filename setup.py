from setuptools import find_packages, setup

setup(
    name="civ4-mp.pylobby",
    version="2.0.0",
    author="Zulan, Dingus",
    python_requires=">=3.7",
    packages=find_packages(),
    scripts=["bin/civgs", "bin/civpb-kill"],
    entry_points="""
      [console_scripts]
      civgs-login=pylobby:login
      civgs-login=pylobby:gamebrowser
      """,
    install_requires=["click", "click_log", "prometheus_client"],
)
