from setuptools import find_packages, setup

setup(
    name="civ4-mp.pylobby",
    version="2.0.0",
    author="Zulan, Dingus",
    python_requires=">=3.7",
    packages=find_packages(),
    entry_points="""
      [console_scripts]
      civgs-login=pylobby:login_main
      civgs-gamebrowser=pylobby:gamebrowser_main
      """,
    install_requires=["click", "click_log", "prometheus_client"],
)
