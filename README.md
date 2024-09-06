# Thesis_Scripts-Assess_of_DAST_Tools_against_OWASP_Top_10_vulns
- [x] Finished
- [ ] Add more modularity to the weights latex table generation
- [ ] Solve some minor bugs about the name of the tools in some the latex tables generated
- [ ] Rewrite some parts of the code to make it more readable

## Index
- [Description](#description)
- [Technologies used](#technologies-used)
- [To run this project](#to-run-this-project)
- [Notes important to read](#notes-important-to-read)
- [Authors](#authors)

## Description
The main objetive for this repository is to disclose the scripts used during the thesis "Evaluation of Dynamic Analysis Tools in detecting OWASP Top 10 Vulnerabilities" @University of Coimbra, Master of Cybersecurity. <br>
These scritps had a fundamental goal to execute several tasks that helped to make the process of assess tools more easy and more intuitive:
- collect what each tool classify during the execution of the workload defined
- countabilization of semi-metrics like TPs, FNs, FPs and TNs, in order to calcute after the real metrics
- generation of excel files to syntetize the results obtained by the scripts, these can be already filled or to be filled
- generation of latex code to form tables with some of the results obtained and to written them on the thesis

Some templates regarding the excel and text files are provided for the following reasons:
- checkmark list about the vulnerable, non-vulnerable and "not making" sense instances in the workload, the last says respect to the cases detected by the tools that aren't vulnerable at all or don't ressemble the vulnerability detected (template/results/experience.xlsx and template/results/experience_fp.xlsx)
- excel file to save the results obtained by the tools in the workload, individually, combinations of 2 and 3 tools not using weights. These will be used to calculate the metrics, namely recall, informedness*recall, f-measure and markedness and later to generate the latex tables about this information (template/LATEX/top_comb2_comb3/METRICS.xlsx)
- excel files regarding the combinations of 2 tools with weights that can be useful to better manage the results obtained by the tools in each vulnerability (template/top_vuln/COMB_ONLYNEW.xlsx and template/top_vuln/top_vuln_comb2.xlsx)
- the folder template/setup provide files that help to setup what is evaluate and how:
  - what applications are used in the worklaod (template/setup/Applications.txt)
  - what tools are evaluated (template/setup/Tools.txt)
  - what vulnerabilities are taken into account (template/setup/Vulnerabilities.txt)
  - possible_vulns folder says respect to the vulnerabilties that each used tool can detect

#### Main Languages:
![](https://img.shields.io/badge/Python-333333?style=flat&logo=python&logoColor=4F74DA)

## Technologies used:
1. Python
    - [Version 3.9](https://www.python.org/downloads/release/python-390/)
2. Libraries:<br>
    - [Xml.dom](https://docs.python.org/3/library/xml.dom.html)
    - [Pandas](https://pandas.pydata.org)
    - [Itertools](https://docs.python.org/3/library/itertools.html)


## To run this project:
Here there is a central script, that will calculate and gather the results obtained by all the tools in all types of applications. So, every task will essential start from the main script, even the later generation of latex tables and excel files. The rest of the scripts will be only used to generate latex tables or to collect the expected results of the WAVSEP Benchmark platform.
1. expected folder
   Since the WAVSEP Benchmark doesn't provide an checkmark list of the testcases, was created a script to collect this information:
   * Unzip the wavsep.zip file
   * Run the following command:
     ```shellscript
     [your-disk]:[name-path]\template\expected> python expected_cases.py > wavsep.csv
     ```
     
2. main script <br>
   Based on the "configurations" made in the setup folder will execute its tasks:
   * Unzip the results.zip file in the template/results folder
   * Run the following command:
     ```shellscript
     [your-disk]:[name-path]\template> python script.py
     ```
     
     This will generate an output with the information about the results achieved by the tools (TPs, FNs, FPs and TNs) for every application, regarding each type of analysis. Will be also generated the following files:
     - weights file (WEIGHTS.txt)
     - a file to help in calculation of the metrics in combination of 2 tools with weights (FINAL_VULNING_2.txt)
     - latex tables for OWASP Benchmark and WAVSEP Benchmark (LATEX_benchmark_apps.txt)
     - latex tables for the other web applications (LATEX_geral_apps.txt)
     
4. minor scrips  <br>
   Here will be executed small scripts for generating the latex tables that still missing:
   * Generation of latex tables for individual tools, combinations of 2 and 3 tools not using weights:
     ```shellscript
     [your-disk]:[name-path]\template\LATEX\top_comb2_comb3> python top_comb.py
     ```
   * Generation of latex tables for combinations of 2 tools with weights:
     ```shellscript
     [your-disk]:[name-path]\regular_apps\LATEX\top_vuln> python top_vuln.py
     ```
   * Generation of latex tables for the weights:
     ```shellscript
     [your-disk]:[name-path]\regular_apps\LATEX\weights_table> python weights_table.py
     ```

## Notes important to read
- To know more about the work conducted and how these scripts helped, read the following thesis on [ADD LINK WHEN AVAILABLE]
- The #template folder contains a template of how the folders, when used, should be displayed. Just unzip the template.zip file
- The folder resources contains the folders used during the analysis conducted on the thesis
- After generated, the "WEIGHTS.txt" file should be move to the LATEX/weights_table folder to allow the generation of latex tables for the weights used in combination of 2 tools using weights
- As already stated, the setup folder allows the configuration of the elements used to conduct the evaluatio here done, if you change them remember you probably must have to change another files, either code or excel. For now this will be left like this, but in the future the goal will be to provide a bit more freedom



## Authors:
- [João Silva](https://github.com/joaosilva21)
