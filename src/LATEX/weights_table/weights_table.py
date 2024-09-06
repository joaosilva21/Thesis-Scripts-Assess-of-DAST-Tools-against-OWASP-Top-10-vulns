import pandas as pd, math, re
import itertools
import copy


def main():
    LATEX = open("LATEX_WEIGHTS.txt", "w")

    vulns = {"Bypass Authorization": "Bypassing Authorization",
             "Path Traversal": "Path Traversal",
             "Remote File Inclusion": "Remote File Inclusion",
             "CSRF": "Cross-Site Request Forgery",
             "Transmission of Information in Cleartext": "Transmission of Information in Cleartext",
             "Untrusted/Invalid TLS certificate": "Untrusted/Invalid TLS certificate",
             "Command Injection": "Command Injection",
             "SQL Injection": "SQL Injection",
             "LDAP Injection": "LDAP Injection",
             "XSS": "Cross-Site Scripting",
             "XPath Injection": "XPath Injection",
             "HTTP Response Splitting": "HTTP Response Splitting",
             "Exposed Improper Error Handling": "Exposed Improper Error Handling",
             "Bad Security Design of Form Fields": "Bad Security Design of Form Fields",
             "Method Tampering": "Method Tampering",
             "XXE": "XML External Entities",
             "Bad Programming of Cookies": "Bad Programming of Cookies",
             "Hardcoded Secret": "Insecure Use of Hard Coded Constants",
             "Vulnerable Outdated Component": "Insecure/Vulnerable Third-Party Software",
             "Bypass Authentication": "Bypassing Authentication",
             "Brute Force Attack": "Brute Force Attacks",
             "Session Fixation": "Session Fixation",
             "Insecure scope of Cookies": "Insecure Scope of Cookies",
             "Insecure Deserialization": "Insecure Deserialization",
             "Improper Output Neutralization for Logs": "Improper Output Neutralization for Logs",
             "SSRF": "Server-Side Request Forgery"
            }
    vuln_list = list(vulns.keys())

    lines = open("WEIGHTS.txt", "r").readlines()
    num = 1

    LATEX.write("\\begin{scriptsize}\n")
    LATEX.write("\\centering\n")
    LATEX.write("\\begin{longtable}{|>{\\columncolor{lightlightgray}}wc{0.6in} | *{4}{wc{0.85cm}|}  >{\\columncolor{lightlightgray}}wc{0.6in} | *{4}{wc{0.85cm}|} m{}}\n")
    LATEX.write("\\hline\n")

    for l in lines:
        lin = l[:-1]
        #print(lin)

        if lin in vuln_list:
            #print(vulns[lin])
            if num == 1:
                
                index_vuln = vuln_list.index(lin)
                #print(vulns[lin], index_vuln)
                LATEX.write("\\rowcolor{lightlightgray} Vulnerability & \\multicolumn{4}{c|}{" + vulns[vuln_list[index_vuln]] + "} & Vulnerability & \\multicolumn{5}{c|}{" + vulns[vuln_list[index_vuln+1]] + "}\\\\\n")
                LATEX.write("\\hline\n")
                LATEX.write("\\rowcolor{lightlightgray} Tool & 1 & 2 & 3 & 4 & Tool & 1 & 2 & 3 & 4\\\\\n")
                LATEX.write("\\hline\n")

            #print(num)
            num = 1 + (0 if num%2==0 else 1)
        else:
            if num == 1:
                if len(l[:-1].split(" ")) != 1:
                    index_line = lines.index(l)
                    #LATEX.write(
                    part1 = lines[index_line-9][:-1].split(" ")
                    part1 = [str(round(float(x), 4)) if x.replace(".", "", 1).isdigit() else x for x in part1]
                    part2 = lines[index_line][:-1].split(" ")
                    part2 = [str(round(float(x), 4)) if x.replace(".", "", 1).isdigit() else x for x in part2]
                    LATEX.write(" & ".join(part1+part2)+"\\\\\n\\hline\n")

    LATEX.write("\\rowcolor{lightlightgray} \\multicolumn{10}{|c|}{1 - Business Critical | 2 - Heightened Critical | 3 - Best Effort | 4 - Minimum Effort}\\\\\n")
    LATEX.write("\\hline\n")
    LATEX.write("\\caption{Weights of each tool for each scenario regarding all the vulnerabilities}\n")
    LATEX.write("\\label{tab:Weights of each tool for each scenario regarding all the vulnerabilities}\n")
    LATEX.write("\\end{longtable}\n")
    LATEX.write("\\end{scriptsize}\n")



if __name__=="__main__":
    main()