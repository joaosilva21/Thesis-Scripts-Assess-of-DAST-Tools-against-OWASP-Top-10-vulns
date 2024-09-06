import pandas as pd, math, re
import itertools
import copy


def main():
    #LATEX = open("LATEX/top_comb2_comb3/LATEX_COMB2.txt", "w")
    #LATEX = open("LATEX/top_comb2_comb3/LATEX_COMB3.txt", "w")

    tool_dic = {"OWASP ZAP":"A", "BurpSuite":"B", "Acunetix":"C", "Iron Wasp":"D", "Wapiti":"E", "OWASP ZAP Plugins":"F"}
    tool_dic_reverse = {"A":"OWASP ZAP", "B":"Burp Suite", "C":"Acunetix", "D":"Iron Wasp", "E":"Wapiti", "F":"OWASP ZAP + Plugins"}
    scenarios_indx = ["Business Critical", "Heightened Critical", "Best Effort", "Minimum Effort"]
    files = {"Comb2": ["\\caption{Ranking of Combination of 2 Tools by scenario}\n\\label{tab: Ranking of Combination of 2 Tools by scenario}\n", "LATEX_COMB2.txt"], 
             "Comb3": ["\\caption{Ranking of Combination of 3 Tools by scenario}\n\\label{tab: Ranking of Combination of 3 Tools by scenario}\n", "LATEX_COMB3.txt"]}

    xl = pd.read_excel('METRICS.xlsx', sheet_name=None)

    for f in files.keys():
        LATEX = open(files[f][1], "w")
        LATEX.write("\\textbf{Results obtained in " + f + "}\\newline\n\n")
        scenarios = {"Business Critical": [], "Heightened Critical": [], "Best Effort": [], "Minimum Effort": []}
        scenario_indx = 0

        for index, row in xl[f].iterrows():
            r = []
            for column, value in row.items():
                r.append(str(value).replace('\n', ' ').replace('\r', ''))

            if r[0] == "nan":
                scenario_indx += 1
            elif r[0] != "Tool":
                tools = r[0].replace("'", "").split(",")
                if len(tools) > 1:
                    if len(tools) > 2:
                        tools[1] = tools[1][1:]
                        tools[2] = tools[2][1:]
                    else:
                        tools[1] = tools[1][1:]
                r[0] = tool_dic[tools[0]] + (", " + tool_dic[tools[1]] if len(tools) > 1 else "") + (", " + tool_dic[tools[2]] if len(tools) > 2 else "")

                scenarios[scenarios_indx[scenario_indx]].append(r) 
            else:
                pass

        
        LATEX.write("\\begin{scriptsize}\n")
        LATEX.write("\\centering\n")
        LATEX.write("\\begin{longtable}{|>{\\columncolor{lightgray}}wc{0.4in} | *{4}{wc{0.35cm}|} *{2}{>{\\columncolor{anti-flashwhite}}wc{0.4in}|} >{\\columncolor{lightgray}}wc{0.4in} | *{4}{wc{0.35cm}|} *{2}{>{\\columncolor{anti-flashwhite}}wc{0.4in}|}m{}}\n")
        LATEX.write("\\hline\n")

        LATEX.write("\\rowcolor{lightgray} \\multicolumn{5}{|c|}{Business Critical} & Metric & Tiebreaker & \\multicolumn{5}{c|}{Heightened Critical} & Metric & Tiebreaker\\\\\n")
        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightgray} Comb. & TP & FN & FP & TN & Recall & Precison & Comb. & TP & FN & FP & TN & Rec.*Infor. & Recall\\\\\n")
        LATEX.write("\\hline\n")

        for k, k2 in zip(scenarios["Business Critical"], scenarios["Heightened Critical"]):
            LATEX.write(k[0] + " & " + k[3] + " & " + k[4] + " & " + k[5] + " & " + k[6] + " & " + str(round(float(k[8])*100, 2)) + "\\% & " + str(round(float(k[12])*100, 2)) + "\\% & " + k2[0] + " & " + k2[3] + " & " + k2[4] + " & " + k2[5] + " & " + k2[6] + " & " +  str(round(float(k2[9])*100, 2)) + "\\% & " + str(round(float(k2[8])*100, 2)) + "\\%\\\\\n")
            LATEX.write("\\hline\n")

        LATEX.write("\\rowcolor{lightgray} \\multicolumn{5}{|c|}{Best Effort} & Metric & Tiebreaker & \\multicolumn{5}{c|}{Minimum Effort} & Metric & Tiebreaker\\\\\n")
        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightgray} Comb. & TP & FN & FP & TN & F-measure & Recall & Comb. & TP & FN & FP & TN & Markedness & Precision\\\\\n")
        LATEX.write("\\hline\n")

        for k, k2 in zip(scenarios["Best Effort"], scenarios["Minimum Effort"]):
            LATEX.write(k[0] + " & " + k[3] + " & " + k[4] + " & " + k[5] + " & " + k[6] + " & " + str(round(float(k[10])*100, 2)) + "\\% & " + str(round(float(k[8])*100, 2)) + "\\% & " + k2[0] + " & " + k2[3] + " & " + k2[4] + " & " + k2[5] + " & " + k2[6] + " & " +  str(round(float(k2[11])*100, 2)) + "\\% & " + str(round(float(k2[12])*100, 2)) + "\\%\\\\\n")
            LATEX.write("\\hline\n")
        
        LATEX.write("\\rowcolor{lightgray}\\multicolumn{14}{|c|}{A - OWASP ZAP | B - Burp Suite | C - Iron Wasp | D - Acunetix | E - Wapiti | F - OWASP ZAP + Plugins}\\\\\n")
        LATEX.write("\\hline\n")
        LATEX.write(files[f][0])
        LATEX.write("\\end{longtable}\n")
        LATEX.write("\\centering\n")
        LATEX.write("\\end{scriptsize}\n")

        LATEX.write("\n")
        LATEX.write("\n")
        LATEX.write("\n")

if __name__=="__main__":
    main()