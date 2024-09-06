import pandas as pd, math, re
import itertools
import copy


def main():
    LATEX = open("LATEX_VULNS.txt", "w")

    vulns = {"Bypass Authorization": "Bypassing Authorization",
             "Remote File Inclusion": "Remote File Inclusion",
             "Path Traversal": "Path Traversal",
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

    tool_dic = {"OWASPZAP":"A", "BurpSuite":"B", "IronWasp":"C", "Acunetix":"D", "Wapiti":"E", "OWASPZAPPlugins":"F"}

    categories = {"A1": [["Bypass Authorization", "Remote File Inclusion", "Path Traversal", "CSRF"], "A1: Broken Access Control"],
                  "A2": [["Transmission of Information in Cleartext", "Untrusted/Invalid TLS certificate"], "A2: Cryptographic Failures"],
                  "A3": [["Command Injection", "SQL Injection", "LDAP Injection", "XSS", "XPath Injection", "HTTP Response Splitting"], "A3: Injection"],
                  "A4": [["Exposed Improper Error Handling", "Bad Security Design of Form Fields", "Method Tampering"], "A4: Insecure Design"],
                  "A5": [["XXE", "Bad Programming of Cookies", "Hardcoded Secret"], "A5: Security Misconfiguration"],
                  "A6": [["Vulnerable Outdated Component"], "A6: Vulnerable and Outdated Components"], 
                  "A7": [["Bypass Authentication", "Brute Force Attack", "Session Fixation"], "A7: Identification and Authentication Failures"],
                  "A8": [["Insecure scope of Cookies", "Insecure Deserialization"], "A8: Software and Data Integrity Failures"],
                  "A9": [["Improper Output Neutralization for Logs"], "A9: Security Logging and Monitoring Failures"], 
                  "A10": [["SSRF"], "A10: Server-Side Request Forgery"]
                 } 

    scenarios_indx = ["Business Critical", "Heightened Critical", "Best Effort", "Minimum Effort"]

    xl = pd.read_excel('top_vuln_comb2.xlsx', sheet_name=None)

    for cat in categories.keys():
        LATEX.write("\\textbf{\\Large Results obtained in " + categories[cat][1] + "}\\newline\n\n")

        scenarios = {"Business Critical": [], "Heightened Critical": [], "Best Effort": [], "Minimum Effort": []}
        vuln_atual = ""
        vuln_indx = 0

        for index, row in xl[cat].iterrows():
            r = []
            for column, value in row.items():
                r.append(str(value).replace('\n', ' ').replace('\r', ''))
            
            if r[0] == "nan":
                continue
            elif r[0] in categories[cat][0]:
                if vuln_atual == r[0]:
                    vuln_indx += 1
                else:
                    vuln_atual = r[0]
                    vuln_indx = 0
            elif r[0] != "Tool":
                tools = r[0][1:-1].replace("'", "").replace(" ", "").split(",")
                r[0] = tool_dic[tools[0]] + ", " + tool_dic[tools[1]]

                scenarios[scenarios_indx[vuln_indx]].append(r+[vuln_atual]) 
            else:
                pass
            #print(r)
        
        LATEX.write("\\begin{scriptsize}\n")
        LATEX.write("\\centering\n")
        LATEX.write("\\begin{longtable}{|>{\\columncolor{lightlightgray}}wc{0.4in} | *{4}{wc{0.35cm}|} *{2}{>{\\columncolor{anti-flashwhite}}wc{0.4in}|} >{\\columncolor{lightlightgray}}wc{0.4in} | *{4}{wc{0.35cm}|} *{2}{>{\\columncolor{anti-flashwhite}}wc{0.4in}|}m{}}\n")
        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightlightgray}\\multicolumn{14}{|c|}{" + categories[cat][1] + "}\\\\\n")
        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightgray} \\multicolumn{5}{|c|}{Business Critical} & Metric & Tiebreaker & \\multicolumn{5}{c|}{Heightened Critical} & Metric & Tiebreaker\\\\\n")
        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightlightgray} Comb. & TP & FN & FP & TN & Recall & Precison & Comb. & TP & FN & FP & TN & Rec.*Infor. & Recall\\\\\n")
        LATEX.write("\\hline\n")
        
        vuln_latex = ""
        for k, k2 in zip(scenarios["Business Critical"], scenarios["Heightened Critical"]):
            if k[-1] != vuln_latex:
                vuln_latex = k[-1]
                LATEX.write("\\rowcolor{lightlightgray}\\multicolumn{14}{|c|}{" + vulns[vuln_latex] + "}\\\\\n")
                LATEX.write("\\hline\n")
            
            LATEX.write(k[0] + " & " + k[9] + " & " + k[13] + " & " + k[17] + " & " + k[21] + " & " + (str(round(float(k[1])*100, 2)) if k[1] != "nan" else "0.00") + "\\% & " + (str(round(float(k[5])*100, 2)) if k[5] != "nan" else "0.00") + "\\% & " + k2[0] + " & " + k2[10] + " & " + k2[14] + " & " + k2[18] + " & " + k2[22] + " & " +  (str(round(float(k2[2])*100, 2)) if k2[2] != "nan" else "0.00") + "\\% & " + (str(round(float(k2[6])*100, 2)) if k2[6] != "nan" else "0.00")  + "\\%\\\\\n")
            LATEX.write("\\hline\n")

        LATEX.write("\\rowcolor{lightlightgray}\\multicolumn{14}{|c|}{A - OWASP ZAP | B - Burp Suite | C - Iron Wasp | D - Accunetix | E - Wapiti | F - OWASP ZAP + Plugins}\\\\\n")
        LATEX.write("\\hline\n")
        LATEX.write("\\caption{Ranking of combinations of 2 SAST tools regarding their performance in category " + categories[cat][1] + " - Business and Heightened Critical Scenarios}\n")
        LATEX.write("\\label{tab:" + categories[cat][1] + " - Business and Heightened Critical Scenarios}\n")
        LATEX.write("\\end{longtable}\n")
        LATEX.write("\\centering\n")
        LATEX.write("\\end{scriptsize}\n")

        LATEX.write("\n")
        LATEX.write("\n")
        LATEX.write("\n")

        LATEX.write("\\begin{scriptsize}\n")
        LATEX.write("\\centering\n")
        LATEX.write("\\begin{longtable}{|>{\\columncolor{lightlightgray}}wc{0.4in} | *{4}{wc{0.35cm}|} *{2}{>{\\columncolor{anti-flashwhite}}wc{0.4in}|} >{\\columncolor{lightlightgray}}wc{0.4in} | *{4}{wc{0.35cm}|} *{2}{>{\\columncolor{anti-flashwhite}}wc{0.4in}|}m{}}\n")
        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightlightgray}\\multicolumn{14}{|c|}{" + categories[cat][1] + "}\\\\\n")
        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightgray} \\multicolumn{5}{|c|}{Best Effort} & Metric & Tiebreaker & \\multicolumn{5}{c|}{Minimum Effort} & Metric & Tiebreaker\\\\\n")
        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightlightgray} Comb. & TP & FN & FP & TN & F-measure & Recall & Comb. & TP & FN & FP & TN & Markedness & Precision\\\\\n")
        LATEX.write("\\hline\n")
        
        vuln_latex = ""
        for k, k2 in zip(scenarios["Best Effort"], scenarios["Minimum Effort"]):
            if k[-1] != vuln_latex:
                vuln_latex = k[-1]
                LATEX.write("\\rowcolor{lightlightgray}\\multicolumn{14}{|c|}{" + vulns[vuln_latex] + "}\\\\\n")
                LATEX.write("\\hline\n")
            
            LATEX.write(k[0] + " & " + k[11] + " & " + k[15] + " & " + k[19] + " & " + k[23] + " & " + (str(round(float(k[3])*100, 2)) if k[3] != "nan" else "0.00") + "\\% & " + (str(round(float(k[7])*100, 2)) if k[7] != "nan" else "0.00") + "\\% & " + k2[0] + " & " + k2[12] + " & " + k2[16] + " & " + k2[20] + " & " + k2[24] + " & " +  (str(round(float(k2[4])*100, 2)) if k2[4] != "nan" else "0.00") + "\\% & " + (str(round(float(k2[8])*100, 2)) if k2[8] != "nan" else "0.00") + "\\%\\\\\n")
            LATEX.write("\\hline\n")

        LATEX.write("\\rowcolor{lightlightgray}\\multicolumn{14}{|c|}{A - OWASP ZAP | B - Burp Suite | C - Iron Wasp | D - Accunetix | E - Wapiti | F - OWASP ZAP + Plugins}\\\\\n")
        LATEX.write("\\hline\n")
        LATEX.write("\\caption{Ranking of combinations of 2 SAST tools regarding their performance in category " + categories[cat][1] + " - Best and Minimum Effort Scenarios}\n")
        LATEX.write("\\label{tab:" + categories[cat][1] + " - Best and Minimum Effort scenarios}\n")
        LATEX.write("\\end{longtable}\n")
        LATEX.write("\\centering\n")
        LATEX.write("\\end{scriptsize}\n")

        LATEX.write("\n")
        LATEX.write("\n")
        LATEX.write("\n")

        #print(scenarios["Business Critical"])
        #print(scenarios["Heightened Critical"])
        #print(scenarios["Best Effort"])
        #print(scenarios["Minimum Effort"])




if __name__=="__main__":
    main()