import math, itertools, re, copy, pandas as pd
from vulnerability import Vulnerability
from xml.dom import minidom
from functools import cmp_to_key

O_ALL = True
O_BENCHMARKS = True


def compare(x,y):
    if math.floor(x[1]/0.05) > math.floor(y[1]/0.05):
        return -1
    elif math.floor(x[1]/0.05) < math.floor(y[1]/0.05):
        return 1
    else: 
        if x[2] > y[2]:
            return -1
        elif x[2] < y[2]:
            return 1
        else:
            if x[1] > y[1]:
                return -1
            elif x[1] < y[1]:
                return 1
            else:
                return 0

def weights(vulning, metrics):
    ranks = {}
    wghts = {}
    wi = 0.895/7
    x = 0.005
    len_tools = len(vulning["XSS"].items())
    file_weights = open("WEIGHTS.txt", "w")

    for k, v in vulning.items():
        #print(k)
        ranks[k] = [[],[],[],[]]
        wghts[k] = [[],[],[],[]]
        for k2, v2 in v.items():
            metrics[k][k2][0] = recall(vulning[k][k2][0], vulning[k][k2][1])
            metrics[k][k2][1] = recall(vulning[k][k2][0], vulning[k][k2][1])*informedness(vulning[k][k2][0], vulning[k][k2][1], vulning[k][k2][2] + vulning[k][k2][4], vulning[k][k2][3] + vulning[k][k2][5])
            metrics[k][k2][4] = precision(vulning[k][k2][0], vulning[k][k2][2] + vulning[k][k2][4])
            metrics[k][k2][2] = f_measure(metrics[k][k2][4], metrics[k][k2][0])
            metrics[k][k2][3] = markedness(vulning[k][k2][0], vulning[k][k2][1], vulning[k][k2][2] + vulning[k][k2][4], vulning[k][k2][3] + vulning[k][k2][5])
            #print((vulning[k][k2][0], vulning[k][k2][2] + vulning[k][k2][4]))
            #print(k2, "recall:" + str(metrics[k][k2][0]), "recall*informedness:" + str(metrics[k][k2][1]), "f-measure:" + str(metrics[k][k2][2]), "markedness:" + str(metrics[k][k2][3]), "precision:" + str(metrics[k][k2][4]))
            ranks[k][0].append([k2, metrics[k][k2][0], metrics[k][k2][4]])
            ranks[k][1].append([k2, metrics[k][k2][1], metrics[k][k2][0]])
            ranks[k][2].append([k2, metrics[k][k2][2], metrics[k][k2][0]])
            ranks[k][3].append([k2, metrics[k][k2][3], metrics[k][k2][4]])
        
        ranks[k][0] = sorted(ranks[k][0], key=cmp_to_key(compare))
        ranks[k][1] = sorted(ranks[k][1], key=cmp_to_key(compare))
        ranks[k][2] = sorted(ranks[k][2], key=cmp_to_key(compare))
        ranks[k][3] = sorted(ranks[k][3], key=cmp_to_key(compare))

        wghts[k] = [0,0,0,0]
        for i in range(4):
            wghts[k][i] = {}
            temp = [ranks[k][i][0][0]]

            for j in range(len_tools):
                wghts[k][i][ranks[k][i][j][0]] = wi + (len_tools-j-1)*x

                if j != 0:
                    if ranks[k][i][j][1] == ranks[k][i][j-1][1] and ranks[k][i][j][2] == ranks[k][i][j-1][2]:
                        temp.append(ranks[k][i][j][0])
                    else:
                        summ = 0
                        for tmp in temp:
                            summ += wghts[k][i][tmp]
                        
                        for tmp in temp:
                            wghts[k][i][tmp] = summ/len(temp)
                        
                        temp = [ranks[k][i][j][0]]

                if j == len_tools-1:
                    summ = 0
                    for tmp in temp:
                        summ += wghts[k][i][tmp]
                    
                    for tmp in temp:
                        wghts[k][i][tmp] = summ/len(temp)
        
        file_weights.write(k + "\n")
        for k2, v2 in v.items():
            file_weights.write(k2 + " ")
            for i in range(4):
                if i==3:
                    file_weights.write(str(wghts[k][i][k2]) + "\n")
                else:
                    file_weights.write(str(wghts[k][i][k2]) + " ")

        file_weights.write("\n\n")

    return wghts

def analyse_results_weighted(wghts, list_apps, list_tools, comb_2, base_results, cases, cases_benchs, list_vulns):
    benchmarks = ["benchmarkowasp", "wavsep"]
    dic =  {}

    for k in list_vulns.keys():
        dic[k] = [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]]


    FINAL_VULNING_2 = {}
    for k in dic.keys():
        FINAL_VULNING_2[k] = {}

    for sub in comb_2:
        for vuln in dic.keys():
            FINAL_VULNING_2[vuln][sub] = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]

    #print("###################################################################################################")
    #print("######################################### COMBINATIONS 2 #########################################")
    #print("###################################################################################################")
    per_vuln = {}

    for sub in comb_2:
        per_vuln[sub] = copy.deepcopy(dic)

    #GENERAL 
    for a in list_apps:
        for comb in comb_2:
            #MAKING SENSE 
            for i in range(len(cases[a][comb[0]])):
                w0 = 1; w1 = 1
                if cases[a][comb[0]][i][2] == 0:
                    w0 = -1
                
                if cases[a][comb[1]][i][2] == 0:
                    w1 = -1
                
                VULN = cases[a][comb[0]][i][0]

                for j in range(4):
                    if wghts[VULN][j][comb[0]]*w0 + wghts[VULN][j][comb[1]]*w1 >= 0:
                        if cases[a][comb[0]][i][1] == 1:
                            per_vuln[comb][VULN][0][j] += 1
                        else:
                            per_vuln[comb][VULN][2][j] += 1
                    else:
                        if cases[a][comb[0]][i][1] == 1:
                            per_vuln[comb][VULN][1][j] += 1
                        else:
                            per_vuln[comb][VULN][3][j] += 1
            
            #CSRF
            for j in range(4):
                if wghts["CSRF"][j][comb[0]] > wghts["CSRF"][j][comb[1]]:
                    tl = comb[0]
                    per_vuln[comb]["CSRF"][0][j] += list_vulns["CSRF"].tools[tl][a].counting[0]
                    per_vuln[comb]["CSRF"][1][j] += list_vulns["CSRF"].tools[tl][a].counting[1]-list_vulns["CSRF"].tools[tl][a].counting[0]
                    per_vuln[comb]["CSRF"][2][j] += list_vulns["CSRF"].tools[tl][a].counting[2]
                    per_vuln[comb]["CSRF"][3][j] += list_vulns["CSRF"].tools[tl][a].counting[3]-list_vulns["CSRF"].tools[tl][a].counting[2]
                elif wghts["CSRF"][j][comb[0]] < wghts["CSRF"][j][comb[1]]:
                    tl = comb[1]
                    per_vuln[comb]["CSRF"][0][j] += list_vulns["CSRF"].tools[tl][a].counting[0]
                    per_vuln[comb]["CSRF"][1][j] += list_vulns["CSRF"].tools[tl][a].counting[1]-list_vulns["CSRF"].tools[tl][a].counting[0]
                    per_vuln[comb]["CSRF"][2][j] += list_vulns["CSRF"].tools[tl][a].counting[2]
                    per_vuln[comb]["CSRF"][3][j] += list_vulns["CSRF"].tools[tl][a].counting[3]-list_vulns["CSRF"].tools[tl][a].counting[2]
                else:
                    per_vuln[comb]["CSRF"][0][j] += max(list_vulns["CSRF"].tools[comb[0]][a].counting[0], list_vulns["CSRF"].tools[comb[1]][a].counting[0])
                    per_vuln[comb]["CSRF"][1][j] += list_vulns["CSRF"].tools[comb[0]][a].counting[1]-max(list_vulns["CSRF"].tools[comb[0]][a].counting[0], list_vulns["CSRF"].tools[comb[1]][a].counting[0])
                    per_vuln[comb]["CSRF"][2][j] += max(list_vulns["CSRF"].tools[comb[0]][a].counting[2], cases_csrf["CSRF"].tools[comb[1]][a].counting[2])
                    per_vuln[comb]["CSRF"][3][j] += list_vulns["CSRF"].tools[comb[0]][a].counting[3]-max(list_vulns["CSRF"].tools[comb[0]][a].counting[2], cases_csrf["CSRF"].tools[comb[1]][a].counting[2])

    #BENCHMARKS
    for b in benchmarks:
        for comb in comb_2:
            #MAKING SENSE
            for ts1, dn2 in zip(cases_benchs[comb[0]][0][b].values(), cases_benchs[comb[1]][0][b].values()):
                if ts1[0] != "NaN":
                    w0 = 1; w1 = 1
                    if ts1[2] == 0:
                        w0 = -1
                    
                    if dn2[2] == 0:
                        w1 = -1
                    
                    VULN = ts1[0]

                    for j in range(4):
                        if wghts[VULN][j][comb[0]]*w0 + wghts[VULN][j][comb[1]]*w1 >= 0:
                            if ts1[1] == 1:
                                per_vuln[comb][VULN][0][j] += 1
                            else:
                                per_vuln[comb][VULN][2][j] += 1
                        else:
                            if ts1[1] == 1:
                                per_vuln[comb][VULN][1][j] += 1
                            else:
                                per_vuln[comb][VULN][3][j] += 1

    for sub in comb_2:
        for vuln, value in per_vuln[sub].items():
            for i in range(4):
                FINAL_VULNING_2[vuln][sub][0][i] += value[0][i]
                FINAL_VULNING_2[vuln][sub][1][i] += value[1][i]
                FINAL_VULNING_2[vuln][sub][2][i] += value[2][i]
                FINAL_VULNING_2[vuln][sub][3][i] += value[3][i]

    FILE = open("FINAL_VULNING_2.txt", "w")
    for k, v in FINAL_VULNING_2.items():
        FILE.write(k + "\n")
        FILE.write("Tool;Recall;Recall*Informedness;F-measure;Markedness;Tie1;Tie2;Tie3;Tie4;TP;TP;TP;TP;FN;FN;FN;FN;FP;FP;FP;FP;TN;TN;TN;TN;\n")
        
        for k2, v2 in v.items():
            line = str(k2) + ";0;0;0;0;0;0;0;0;"
            for i in range(4):
                for j in range(4):
                    line += str(v2[i][j]) + ";"
            FILE.write(line + "\n")

        FILE.write("\n")
        FILE.write("\n")



def recall(tp, fn):
    if tp+fn == 0:
        return 0

    return tp/(tp+fn)

def informedness(tp, fn, fp, tn):
    if tp+fn == 0 and fp+tn == 0:
        return 0

    if fp+tn == 0:
        return (tp/(tp+fn)+1)/2

    if tp+fn == 0:
        return (- fp/(fp+tn)+1)/2

    return (tp/(tp+fn) - fp/(fp+tn)+1)/2

def markedness(tp, fn, fp, tn):
    if tp+fp == 0 and fn+tn == 0:
        return 0

    if fn+tn == 0:
        return (tp/(tp+fp)+1)/2

    if tp+fp == 0:
        return (- fn/(fn+tn)+1)/2

    return (tp/(tp+fp) - fn/(fn+tn)+1)/2

def precision(tp, fp):
    if tp+fp == 0:
        return 0

    return tp/(tp+fp)

def f_measure(precision, recall):
    if precision+recall == 0:
        return 0
    return (2*precision*recall)/(precision+recall)


def analyse_benchmarks(possible_vulns, tools, tool_vulns, vulns_quant, vulning):
    benchmarkowasp_expected = open("results/Expected/benchmarkowasp.csv")
    wavsep_expected = open("results/Expected/wavsep.csv")
    benchmarks = ["benchmarkowasp", "wavsep"]
    tools = ["OWASP ZAP", "BurpSuite", "Iron Wasp", "Acunetix", "Wapiti", "OWASP ZAP Plugins"]
    comb_2 = list(itertools.combinations(tools, 2))
    comb_3 = list(itertools.combinations(tools, 3))
    overall_results = {}
    overall_results_comb2 = {}
    overall_results_comb3 = {}
    for t in tools:
        overall_results[t] = [0,0,0,0,0,0]
    for comb in comb_2:
        overall_results_comb2[comb] = [0,0,0,0,0,0]
    for comb in comb_3:
        overall_results_comb3[comb] = [0,0,0,0,0,0]

    #LATEX
    latex = {}
    latex_results = {"Bypass Authorization": [0,0,0,0,0,0],
                   "Path Traversal": [0,0,0,0,0,0],
                   "Remote File Inclusion": [0,0,0,0,0,0],
                   "CSRF": [0,0,0,0,0,0],
                   "Transmission of Information in Cleartext": [0,0,0,0,0,0],
                   "Untrusted/Invalid TLS certificate": [0,0,0,0,0,0],
                   "Command Injection": [0,0,0,0,0,0],
                   "SQL Injection": [0,0,0,0,0,0],
                   "LDAP Injection": [0,0,0,0,0,0],
                   "XSS": [0,0,0,0,0,0],
                   "XPath Injection": [0,0,0,0,0,0],
                   "HTTP Response Splitting": [0,0,0,0,0,0],
                   "Exposed Improper Error Handling": [0,0,0,0,0,0],
                   "Bad Security Design of Form Fields": [0,0,0,0,0,0],
                   "Method Tampering": [0,0,0,0,0,0],
                   "XXE": [0,0,0,0,0,0],
                   "Bad Programming of Cookies": [0,0,0,0,0,0],
                   "Hardcoded Secret": [0,0,0,0,0,0],
                   "Vulnerable Outdated Component": [0,0,0,0,0,0],
                   "Bypass Authentication": [0,0,0,0,0,0],
                   "Brute Force Attack": [0,0,0,0,0,0],
                   "Session Fixation": [0,0,0,0,0,0],
                   "Insecure scope of Cookies": [0,0,0,0,0,0],
                   "Insecure Deserialization": [0,0,0,0,0,0],
                   "Improper Output Neutralization for Logs": [0,0,0,0,0,0],
                   "SSRF": [0,0,0,0,0,0]
                  }

    latex_categories = {"A1 Broken Access Control": ["Bypass Authorization", "Path Traversal", "Remote File Inclusion", "CSRF"],
                        "A2 Cryptographic Failure": ["Transmission of Information in Cleartext", "Untrusted/Invalid TLS certificate"],
                        "A3 Injection": ["Command Injection", "SQL Injection", "LDAP Injection", "XSS", "XPath Injection", "HTTP Response Splitting"],
                        "A4 Insecure Design": ["Exposed Improper Error Handling", "Bad Security Design of Form Fields", "Method Tampering"],
                        "A5 Security Misconfiguration": ["XXE", "Bad Programming of Cookies", "Hardcoded Secret"],
                        "A6 Vulnerable and Outdated Components": ["Vulnerable Outdated Component"],
                        "A7 Identification and Authentication Failures": ["Bypass Authentication", "Brute Force Attack", "Session Fixation"],
                        "A8 Software and Data Integrity Failures": ["Insecure scope of Cookies", "Insecure Deserialization"],
                        "A9 Security Logging and Monitoring Failures": ["Improper Output Neutralization for Logs"],
                        "A10 Server-Side Request Forgery": ["SSRF"],
                        }

    latex_vulns = {"Bypass Authorization":"Bypassing Authorization",
                     "Path Traversal":"Path Traversal",
                     "Remote File Inclusion":"Remote File Inclusion",
                     "CSRF": "Cross-Site Request Forgery",
                     "Transmission of Information in Cleartext": "Transmission of Information in Cleartext",
                     "Untrusted/Invalid TLS certificate": "Untrusted/Invalid TLS Certificate",
                     "Command Injection": "OS Command Injection", 
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

    #benchmarkowasp
    map_benchmarkowasp = {"pathtraver": "Path Traversal", "cmdi": "Command Injection", "sqli": "SQL Injection", "ldapi": "LDAP Injection", 
                          "xss": "XSS", "xpathi": "XPath Injection", }
    reverse_map_benchmarkowasp = dict(zip(map_benchmarkowasp.values(), map_benchmarkowasp.keys()))
    cases_benchmarkowasp = {} 

    for line in benchmarkowasp_expected.readlines():
        splitted = line.split(",")
        if splitted[1] in map_benchmarkowasp.keys():
            cases_benchmarkowasp[splitted[0]] = [map_benchmarkowasp[splitted[1]], 1 if splitted[2]=="TRUE" else 0, 0]  #Type of vulnerability, positive or negative, detected or not
        else:
            cases_benchmarkowasp[splitted[0]] = ['NaN', 0, 0]
    

    vulns_benchmarkowasp = {"Path Traversal":[0,0,0,0,0], "CSRF":[0,0,0,0,0], "Command Injection":[0,0,0,0,0], "SQL Injection":[0,0,0,0,0],  #TP, FN, FP, TN
                                "LDAP Injection":[0,0,0,0,0], "XSS":[0,0,0,0,0], "XPath Injection":[0,0,0,0,0], "Bad Programming of Cookies":[0,0,0,0,0],
                                "NaN":[0,0,0,0,0]}
    notmakingsense_vulns_benchmarkowasp =  {"Path Traversal":0, "CSRF":0, "Command Injection":0, "SQL Injection":0,  
                                            "LDAP Injection":0, "XSS":0, "XPath Injection":0, "Bad Programming of Cookies":0, "NaN":0}

    #wavsep
    map_wavsep = {"DOM-XSS": "XSS", "LFI": "SSRF", "OS-Command-Injection": "Command Injection", "Reflected-XSS": "XSS", "RFI": "Remote File Inclusion",
                  "SQL-Injection": "SQL Injection", "Unvalidated-Redirect": "Bypass Authorization", "XXE": "XXE"}
    reverse_map_wavsep = dict(zip(map_wavsep.values(), map_wavsep.keys()))
    cases_wavsep = {} 

    for line in wavsep_expected.readlines():
        splitted = line.split(",")
        
        if splitted[1] in map_wavsep.keys():
            cases_wavsep[splitted[0]] = [map_wavsep[splitted[1]], 1 if splitted[2]=="TRUE" else 0, 0]  #Type of vulnerability, positive or negative, detected or not
        else:
            cases_wavsep[splitted[0]] = ['NaN', 0, 0]
        

    vulns_wavsep = {"Bypass Authorization":[0,0,0,0,0], "Remote File Inclusion":[0,0,0,0,0], "CSRF":[0,0,0,0,0], "Command Injection":[0,0,0,0,0],   #TP, FN, FP, TN
                    "SQL Injection":[0,0,0,0,0], "XSS":[0,0,0,0,0], "XXE":[0,0,0,0,0],
                    "SSRF":[0,0,0,0,0], "NaN":[0,0,0,0,0]}
    notmakingsense_vulns_wavsep =  {"Bypass Authorization":0, "Remote File Inclusion":0, "CSRF":0, "Command Injection":0,   
                                    "SQL Injection":0, "XSS":0, "XXE":0, "SSRF": 0, "NaN":0}

    maps = {"benchmarkowasp": map_benchmarkowasp, "wavsep": map_wavsep}
    reverse_maps = {"benchmarkowasp": reverse_map_benchmarkowasp, "wavsep": reverse_map_wavsep}
    vulns = {"benchmarkowasp": vulns_benchmarkowasp, "wavsep": vulns_wavsep}
    notmakingsense_vulns = {"benchmarkowasp": notmakingsense_vulns_benchmarkowasp, "wavsep": notmakingsense_vulns_wavsep}
    cases = {"benchmarkowasp": cases_benchmarkowasp, "wavsep": cases_wavsep}
    patters = {"benchmarkowasp": "BenchmarkTest[0-9]{5}|$", "wavsep": "[a-zA-Z0-9-]*/Case[0-9]{2}.*jsp|$"}
    
    results = {}
    #results[tool] = (cases, cases_fp, vulns, notmakingsense_vulns)

    #OWASP ZAP
    results["OWASP ZAP"] = analyse_benchmark_owaspzap(maps, reverse_maps, copy.deepcopy(vulns), copy.deepcopy(notmakingsense_vulns), copy.deepcopy(cases), patters, benchmarks, copy.deepcopy(possible_vulns))

    #BurpSuite
    results["BurpSuite"] = analyse_benchmark_burpsuite(maps, reverse_maps, copy.deepcopy(vulns), copy.deepcopy(notmakingsense_vulns), copy.deepcopy(cases), patters, benchmarks, copy.deepcopy(possible_vulns))

    #Iron Wasp
    results["Iron Wasp"] = analyse_benchmark_ironwasp(maps, reverse_maps, copy.deepcopy(vulns), copy.deepcopy(notmakingsense_vulns), copy.deepcopy(cases), patters, benchmarks, copy.deepcopy(possible_vulns))

    #Acunetix
    results["Acunetix"] = analyse_benchmark_acunetix(maps, reverse_maps, copy.deepcopy(vulns), copy.deepcopy(notmakingsense_vulns), copy.deepcopy(cases), patters, benchmarks, copy.deepcopy(possible_vulns))
    
    #Wapiti
    results["Wapiti"] = analyse_benchmark_wapiti(maps, reverse_maps, copy.deepcopy(vulns), copy.deepcopy(notmakingsense_vulns), copy.deepcopy(cases), patters, benchmarks, copy.deepcopy(possible_vulns))
    
    #OWASP ZAP Plugins
    results["OWASP ZAP Plugins"] = analyse_benchmark_owaspzap_plugins(maps, reverse_maps, copy.deepcopy(vulns), copy.deepcopy(notmakingsense_vulns), copy.deepcopy(cases), patters, benchmarks, copy.deepcopy(possible_vulns))
    
    #GET FALSE POSITIVE CASES FROM EACH APPLICATION AND MERGE THEM TOGETHER TO FORM NEGATIVES LIST FORMED BY FALSE POSITIVES THAT DON'T MAKE SENSE
    merge_fp = {}
    fp_cases = {}
    for b in benchmarks:
        merge_fp[b] = []
        fp_cases[b] = copy.deepcopy(vulns[b])

        for t in tools:
            merge_fp[b] = list(set(i for i in merge_fp[b]) | set(i for i in results[t][1][b]))

        for c in merge_fp[b]:
            fp_cases[b][c.split("/")[-1]][0] += 1

        #print(fp_cases[b])


    #SINGULAR
    print("###################################################################################################")
    print("############################################ SINGULAR ############################################")
    print("###################################################################################################")
    for b in benchmarks:
        latex[b] = {}
        for t in tools:
            latex[b][t] = copy.deepcopy(latex_results)

        print("========================= " + b + " =========================")
        for t in tools:
            tp, fn, fp, tn, fpfp, fptn = 0, 0, 0, 0, 0, 0
            print("========================= " + t + " =========================")
            for k, v, v_fp in zip(results[t][2][b].keys(), results[t][2][b].values(), results[t][3][b].values()):
                if k != "NaN":
                    tool_vulns[t][k][0] += v[0]
                    tool_vulns[t][k][1] += v[1]
                    tool_vulns[t][k][2] += v[2]
                    tool_vulns[t][k][3] += v[3]

                    vulning[k][t][0] += v[0]
                    vulning[k][t][1] += v[1]
                    vulning[k][t][2] += v[2]
                    vulning[k][t][3] += v[3]
                    vulning[k][t][4] += v_fp
                    vulning[k][t][5] += fp_cases[b][k][0]-v_fp

                    latex[b][t][k][0] += v[0]
                    latex[b][t][k][1] += v[1]
                    latex[b][t][k][2] += v[2]
                    latex[b][t][k][3] += v[3]
                    latex[b][t][k][4] += v_fp
                    latex[b][t][k][5] += fp_cases[b][k][0]-v_fp

                    tp += v[0]; fn += v[1]; fp += v[2]; tn += v[3]; fpfp += v_fp; fptn += fp_cases[b][k][0]-v_fp
                    print(k + ":", "TP:" + str(v[0]) + "|", "FN:" + str(v[1]) + "|", "FP:" + str(v[2]+v_fp) + "(" + str(v_fp) + ")|", "TN:" + str(v[3]+fp_cases[b][k][0]-v_fp) + "(" + str(fp_cases[b][k][0]-v_fp) + ")")
            print("[" + t + "]:", "TP:" + str(tp) + "|", "FN:" + str(fn) + "|", "FP:" + str(fp+fpfp) + "(" + str(fpfp) + ")|", "TN:" + str(tn+fptn) + "(" + str(fptn) + ")|")
            #print("AAA", results[t][3][b])
            #print("BBB", results[t][1][b])
            overall_results[t][0] += tp; overall_results[t][1] += fn; overall_results[t][2] += fp; overall_results[t][3] += tn; overall_results[t][4] += fpfp; overall_results[t][5] += fptn
            print()
        print()
        print()
    
    #COMBINATIONS 2
    print("###################################################################################################")
    print("######################################### COMBINATIONS 2 #########################################")
    print("###################################################################################################")
    for b in benchmarks:
        print("========================= " + b + " =========================")
        for comb in comb_2:
            tp, fn, fp, tn, fpfp = 0, 0, 0, 0, 0
            results_comb2 = copy.deepcopy(vulns[b])

            #MAKING SENSE
            for ts1, dn2 in zip(results[comb[0]][0][b].values(), results[comb[1]][0][b].values()):
                if ts1[0] != "NaN":
                    if ts1[1] == 1:
                        if ts1[1] == ts1[2] | dn2[2]:
                            results_comb2[ts1[0]][0]+=1
                            tp += 1
                        else:
                            results_comb2[ts1[0]][1]+=1
                            fn += 1
                    else:
                        if ts1[1] == ts1[2] | dn2[2]:
                            results_comb2[ts1[0]][3]+=1
                            tn += 1
                        else:
                            results_comb2[ts1[0]][2]+=1
                            fp += 1
            
            #NOT MAKING SENSE - FALSE POSITIVES NOT INCLUDED BEFORE
            comb_list = list(set(results[comb[0]][1][b]) | set(results[comb[1]][1][b]))
            for i in range(len(comb_list)):
                vuln = comb_list[i].split("/")[-1]
                if vuln != "NaN":
                    results_comb2[vuln][4]+=1
                    fpfp += 1

            print("========================= " + str(comb) + " =========================")
            for k, v, v_fp in zip(results_comb2.keys(), results_comb2.values(), [0]*len(results_comb2)):
                if k != "NaN":
                    print(k + ":", "TP:" + str(v[0]) + "|", "FN:" + str(v[1]) + "|", "FP:" + str(v[2]+v[4]) + "(" + str(v[4]) + ")|", "TN:" + str(v[3]+fp_cases[b][k][0]-v[4]) + "(" + str(fp_cases[b][k][0]-v[4]) + ")|")
            fptn = (sum([vk[0] for vk in fp_cases[b].values()]) - fpfp)

            print("[" + str(comb) + "]:", "TP:" + str(tp) + "|", "FN:" + str(fn) + "|", "FP:" + str(fp+fpfp) + "(" + str(fpfp) + ")|", "TN:" + str(tn+fptn) + "(" + str(fptn) + ")|")
            overall_results_comb2[comb][0] += tp; overall_results_comb2[comb][1] += fn; overall_results_comb2[comb][2] += fp; overall_results_comb2[comb][3] += tn; overall_results_comb2[comb][4] += fpfp; overall_results_comb2[comb][5] += fptn
            print()
        print()
        print()

    #COMBINATIONS 3
    print("###################################################################################################")
    print("######################################### COMBINATIONS 3 #########################################")
    print("###################################################################################################")
    for b in benchmarks:
        print("========================= " + b + " =========================")
        for comb in comb_3:
            tp, fn, fp, tn, fpfp = 0, 0, 0, 0, 0
            results_comb3 = copy.deepcopy(vulns[b])

            #MAKING SENSE
            for ts1, dn2, dr3 in zip(results[comb[0]][0][b].values(), results[comb[1]][0][b].values(), results[comb[2]][0][b].values()):
                if ts1[0] != "NaN":
                    if ts1[1] == 1:
                        if ts1[1] == ts1[2] | dn2[2] | dr3[2]:
                            results_comb3[ts1[0]][0]+=1
                            tp += 1
                        else:
                            results_comb3[ts1[0]][1]+=1
                            fn += 1
                    else:
                        if ts1[1] == ts1[2] | dn2[2] | dr3[2]:
                            results_comb3[ts1[0]][3]+=1
                            tn += 1
                        else:
                            results_comb3[ts1[0]][2]+=1
                            fp += 1
            
            #NOT MAKING SENSE - FALSE POSITIVES NOT INCLUDED BEFORE
            comb_list = list(set(results[comb[0]][1][b]) | set(results[comb[1]][1][b]) | set(results[comb[2]][1][b]))
            for i in range(len(comb_list)):
                vuln = comb_list[i].split("/")[-1]
                if vuln != "NaN":
                    results_comb3[vuln][4]+=1
                    fpfp += 1

            print("========================= " + str(comb) + " =========================")
            for k, v, v_fp in zip(results_comb3.keys(), results_comb3.values(), [0]*len(results_comb3)):
                if k != "NaN":
                    print(k + ":", "TP:" + str(v[0]) + "|", "FN:" + str(v[1]) + "|", "FP:" + str(v[2]+v[4]) + "(" + str(v[4]) + ")|", "TN:" + str(v[3]+fp_cases[b][k][0]-v[4]) + "(" + str(fp_cases[b][k][0]-v[4]) + ")|")
            fptn = (sum([vk[0] for vk in fp_cases[b].values()]) - fpfp)
            
            print("[" + str(comb) + "]:", "TP:" + str(tp) + "|", "FN:" + str(fn) + "|", "FP:" + str(fp+fpfp) + "(" + str(fpfp) + ")|", "TN:" + str(tn+fptn) + "(" + str(fptn) + ")|")
            overall_results_comb3[comb][0] += tp; overall_results_comb3[comb][1] += fn; overall_results_comb3[comb][2] += fp; overall_results_comb3[comb][3] += tn; overall_results_comb3[comb][4] += fpfp; overall_results_comb3[comb][5] += fptn
            print()
        print()
        print()
    
    if O_BENCHMARKS == True:
        #OVERALL
        print("###################################################################################################")
        print("######################################### OVERALL RESULTS #########################################")
        print("###################################################################################################")
        for t, res in overall_results.items():
            print("[" + str(t) + "]:", "TP:" + str(res[0]) + "|", "FN:" + str(res[1]) + "|", "FP:" + str(res[2]+res[4]) + "(" + str(res[4]) + ")|", "TN:" + str(res[3]+res[5]) + "(" + str(res[5]) + ")|")
        print()

        for comb, res in overall_results_comb2.items():
            print("[" + str(comb) + "]:", "TP:" + str(res[0]) + "|", "FN:" + str(res[1]) + "|", "FP:" + str(res[2]+res[4]) + "(" + str(res[4]) + ")|", "TN:" + str(res[3]+res[5]) + "(" + str(res[5]) + ")|")
        print()

        for comb, res in overall_results_comb3.items():
            print("[" + str(comb) + "]:", "TP:" + str(res[0]) + "|", "FN:" + str(res[1]) + "|", "FP:" + str(res[2]+res[4]) + "(" + str(res[4]) + ")|", "TN:" + str(res[3]+res[5]) + "(" + str(res[5]) + ")|")
        print()

    LATEX = open("LATEX_benchmark_apps.txt", "w")
    t_1st = ["OWASP ZAP", "BurpSuite", "Iron Wasp"]
    t_2nd = ["Acunetix", "Wapiti", "OWASP ZAP Plugins"]
    for bench in benchmarks:
        LATEX.write("\\textbf{\\large Results obtained in " + bench + "}\\newline\n\n")

        LATEX.write("\\begin{tiny}\n")
        LATEX.write("\\captionsetup{font=footnotesize}\n")
        LATEX.write("\\centering\n")
        LATEX.write("\\setlength{\\tabcolsep}{3pt}\n")
        LATEX.write("\\begin{longtable}{*{1}{|wc{0.1in}|m{1.55in}|} *{3}{>{\\columncolor{anti-flashwhite}}wc{0.35cm}|}")

        flg = 0
        for t in t_1st:
            LATEX.write(" *{4}{" + ("" if flg == 0 else ">{\\columncolor{anti-flashwhite}}") + "wc{0.35cm}|}")
            flg ^=1

        LATEX.write("}\n")

        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightgray}\\multicolumn{5}{|c|}{Vulnerability} & \\multicolumn{" + str(4*len(t_1st)) + "}{c|}{Tools} \\\\\n")
        LATEX.write("\\hline\n")
        
        LATEX.write("\\rowcolor{lightgray} ID & \\multicolumn{1}{c}{Name} &  \\multicolumn{3}{|c|}{Total}")
        for t in t_1st:
            LATEX.write(" & \\multicolumn{4}{c|}{" + t + "}")

        LATEX.write("\\\\\n\\hline\n")
        
        for c, vulns in latex_categories.items():
            c_splitted = c.split(" ")
            LATEX.write("\\rowcolor{lightlightgray} " + c_splitted[0] + " & " + " ".join(c_splitted[1:]) + " & P & N & FPFP")
            LATEX.write(" & TP & FN & FP & TN"*len(t_1st))
            
            LATEX.write("\\\\\n")
            LATEX.write("\\hline"+ "\n")

            for k in vulns:
                LATEX.write("\\multicolumn{2}{|m{1.7in}|}{" + latex_vulns[k] + "} & " +  str(latex[bench]["OWASP ZAP"][k][0]+latex[bench]["OWASP ZAP"][k][1]) +  " & " + str(latex[bench]["OWASP ZAP"][k][2]+latex[bench]["OWASP ZAP"][k][3]) +  " & " + str(latex[bench]["OWASP ZAP"][k][4]+latex[bench]["OWASP ZAP"][k][5]))
                for t in t_1st:
                    LATEX.write(" & " + str(latex[bench][t][k][0]) + " & " + str(latex[bench][t][k][1]) + " & " + str(latex[bench][t][k][2]+latex[bench][t][k][4]) + " & " + str(latex[bench][t][k][3]+latex[bench][t][k][5]))

                LATEX.write("\\\\\n")
                LATEX.write("\\hline"+ "\n")
            LATEX.write("\n")

        LATEX.write("\\caption{DAST tools output in relation to " + bench +  " - Part1}\n")
        LATEX.write("\\label{table:DAST tools output in relation to " + bench +  " - Part1}\n")
        LATEX.write("\\end{longtable}\n")
        LATEX.write("\\end{tiny}\n")
        
        LATEX.write("\n\n\n")
        
        LATEX.write("\\begin{tiny}\n")
        LATEX.write("\\captionsetup{font=footnotesize}\n")
        LATEX.write("\\centering\n")
        LATEX.write("\\setlength{\\tabcolsep}{3pt}\n")
        LATEX.write("\\begin{longtable}{*{1}{|wc{0.1in}|m{1.55in}|} *{3}{>{\\columncolor{anti-flashwhite}}wc{0.35cm}|}")

        flg = 0
        for t in t_2nd:
            LATEX.write(" *{4}{" + ("" if flg == 0 else ">{\\columncolor{anti-flashwhite}}") + "wc{0.35cm}|}")
            flg ^=1

        LATEX.write("}\n")

        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightgray}\\multicolumn{5}{|c|}{Vulnerability} & \\multicolumn{" + str(4*len(t_2nd)) + "}{c|}{Tools} \\\\\n")
        LATEX.write("\\hline\n")
        
        LATEX.write("\\rowcolor{lightgray} ID & \\multicolumn{1}{c}{Name} &  \\multicolumn{3}{|c|}{Total}")
        for t in t_2nd:
            LATEX.write(" & \\multicolumn{4}{c|}{" + t + "}")

        LATEX.write("\\\\\n\\hline\n")
        
        for c, vulns in latex_categories.items():
            c_splitted = c.split(" ")
            LATEX.write("\\rowcolor{lightlightgray} " + c_splitted[0] + " & " + " ".join(c_splitted[1:]) + " & P & N & FPFP")
            LATEX.write(" & TP & FN & FP & TN"*len(t_2nd))
            
            LATEX.write("\\\\\n")
            LATEX.write("\\hline"+ "\n")

            for k in vulns:
                LATEX.write("\\multicolumn{2}{|m{1.7in}|}{" + latex_vulns[k] + "} & " +  str(latex[bench]["OWASP ZAP"][k][0]+latex[bench]["OWASP ZAP"][k][1]) +  " & " + str(latex[bench]["OWASP ZAP"][k][2]+latex[bench]["OWASP ZAP"][k][3]) +  " & " + str(latex[bench]["OWASP ZAP"][k][4]+latex[bench]["OWASP ZAP"][k][5]))
                for t in t_2nd:
                    LATEX.write(" & " + str(latex[bench][t][k][0]) + " & " + str(latex[bench][t][k][1]) + " & " + str(latex[bench][t][k][2]+latex[bench][t][k][4]) + " & " + str(latex[bench][t][k][3]+latex[bench][t][k][5]))

                LATEX.write("\\\\\n")
                LATEX.write("\\hline"+ "\n")
            LATEX.write("\n")

        LATEX.write("\\caption{DAST tools output in relation to " + bench +  " - Part2}\n")
        LATEX.write("\\label{table:DAST tools output in relation to " + bench +  " - Part2}\n")
        LATEX.write("\\end{longtable}\n")
        LATEX.write("\\end{tiny}\n")
        
        LATEX.write("\n\n")
        LATEX.write("\\newpage")

        LATEX.write("\n\n\n")

    return tool_vulns, vulns_quant, vulning, results

def analyse_benchmark_owaspzap(maps, reverse_maps, vulns, notmakingsense_vulns, cases, patters, benchmarks, possible_vulns):
    cases_fp = {}

    for benchmark in benchmarks:
        cases_fp[benchmark] = []
        #Convert Path Traversal to SSRF, because they actually are SSRF (this vulnerability could appear in RFI, LFI, Path Traversal form...)
        if benchmark == "wavsep":
            possible_vulns["OWASP ZAP"]["Path Traversal"] = "SSRF"

        file = minidom.parse("results/OWASP ZAP/" + benchmark + ".xml")
        types_alerts = file.getElementsByTagName('alertitem')
        for alertitem in types_alerts:
            type_alert = alertitem.getElementsByTagName('name')[0].firstChild.data
            if type_alert in list(possible_vulns["OWASP ZAP"].keys())[:-4]: #temporariamente tirar csrf, cookies e vulnerable outdated components
                alerts = alertitem.getElementsByTagName('instance')
                for instance in alerts:
                    case = re.findall(patters[benchmark], instance.getElementsByTagName('uri')[0].firstChild.data)[0]
                    #print(case, instance.getElementsByTagName('uri')[0].firstChild.data)
                    if case != "":
                        pos = case.find("?")
                        if pos!=-1:
                            case = case[:pos]
                        #print(case)
                        type_vuln = maps[benchmark][reverse_maps[benchmark][possible_vulns["OWASP ZAP"][type_alert]]]
                        if type_vuln == cases[benchmark][case][0]:
                            cases[benchmark][case][2] = 1
                        else:
                            if case+"/"+type_vuln not in cases_fp[benchmark]:
                                cases_fp[benchmark].append(case+"/"+type_vuln)
                                notmakingsense_vulns[benchmark][type_vuln] += 1

        #results
        for case in cases[benchmark].values():
            #print(case)
            if case[1]==1:
                if case[1]==case[2]:
                    vulns[benchmark][case[0]][0]+=1
                else:
                    vulns[benchmark][case[0]][1]+=1
            else:
                if case[1]==case[2]:
                    vulns[benchmark][case[0]][3]+=1
                else:
                    vulns[benchmark][case[0]][2]+=1
        
    return cases, cases_fp, vulns, notmakingsense_vulns

def analyse_benchmark_burpsuite(maps, reverse_maps, vulns, notmakingsense_vulns, cases, patters, benchmarks, possible_vulns):
    cases_fp = {}

    for benchmark in benchmarks:
        cases_fp[benchmark] = []
        if benchmark == "wavsep":
            possible_vulns["BurpSuite"]["File path manipulation"] = "SSRF"
            possible_vulns["BurpSuite"]["File path traversal"] = "SSRF"
    
        file = minidom.parse("results/BurpSuite/" + benchmark + ".xml")
        issues = file.getElementsByTagName('issue')

        for issue in issues:
            type_alert = issue.getElementsByTagName('name')[0].firstChild.data
            if type_alert in list(possible_vulns["BurpSuite"].keys())[:-4]: #temporariamente tirar csrf, cookies e vulnerable outdated components
                case = re.findall(patters[benchmark], issue.getElementsByTagName('path')[0].firstChild.data)[0]
                if case != "":
                    pos = case.find("?")
                    if pos!=-1:
                        case = case[:pos]
                    #print(case)
                    type_vuln = maps[benchmark][reverse_maps[benchmark][possible_vulns["BurpSuite"][type_alert]]]
                    if type_vuln == cases[benchmark][case][0]:
                        cases[benchmark][case][2] = 1
                    else:
                        if case+"/"+type_vuln not in cases_fp[benchmark]:
                            cases_fp[benchmark].append(case+"/"+type_vuln)
                            notmakingsense_vulns[benchmark][type_vuln] += 1

        #results
        for case in cases[benchmark].values():
            #print(case)
            if case[1]==1:
                if case[1]==case[2]:
                    vulns[benchmark][case[0]][0]+=1
                else:
                    vulns[benchmark][case[0]][1]+=1
            else:
                if case[1]==case[2]:
                    vulns[benchmark][case[0]][3]+=1
                else:
                    vulns[benchmark][case[0]][2]+=1

    return cases, cases_fp, vulns, notmakingsense_vulns

def analyse_benchmark_ironwasp(maps, reverse_maps, vulns, notmakingsense_vulns, cases, patters, benchmarks, possible_vulns):
    cases_fp = {}

    for benchmark in benchmarks:
        cases_fp[benchmark] = []
        if benchmark == "wavsep":
            possible_vulns["Iron Wasp"]["Local File Include Found"] = "SSRF"
    
       #print(reverse_maps[benchmark])
        actual_vuln = ""
        file = open("results/Iron Wasp/" + benchmark + ".html")
        for line in file.readlines():
            line = line[:-1]
            if re.search("'#finding[0-9]+'><span class='ic(r|o|y|b|g)'>", line):
                #print(line)
                actual_vuln = re.findall("[a-zA-Z -]+<", line)[0][:-1]
            elif re.search("<span class='index_finding_url'>", line):
                #print(line)
                if actual_vuln in list(possible_vulns["Iron Wasp"].keys())[:-1]: #cookies
                    case = re.findall(patters[benchmark], line)[0]
                    if case != "":
                        pos = case.find("?")
                        if pos!=-1:
                            case = case[:pos]
                        #print(actual_vuln, possible_vulns["Iron Wasp"][actual_vuln])
                        if possible_vulns["Iron Wasp"][actual_vuln] not in list(reverse_maps[benchmark].keys()):
                            continue
                        type_vuln = maps[benchmark][reverse_maps[benchmark][possible_vulns["Iron Wasp"][actual_vuln]]]
                        if type_vuln == cases[benchmark][case][0]:
                            cases[benchmark][case][2] = 1
                        else:
                            if case+"/"+type_vuln not in cases_fp[benchmark]:
                                cases_fp[benchmark].append(case+"/"+type_vuln)
                                notmakingsense_vulns[benchmark][type_vuln] += 1

        #results
        for case in cases[benchmark].values():
            if case[1]==1:
                if case[1]==case[2]:
                    vulns[benchmark][case[0]][0]+=1
                else:
                    vulns[benchmark][case[0]][1]+=1
            else:
                if case[1]==case[2]:
                    vulns[benchmark][case[0]][3]+=1
                else:
                    vulns[benchmark][case[0]][2]+=1

    return cases, cases_fp, vulns, notmakingsense_vulns

def analyse_benchmark_acunetix(maps, reverse_maps, vulns, notmakingsense_vulns, cases, patters, benchmarks, possible_vulns):
    cases_fp = {}

    for benchmark in benchmarks:
        cases_fp[benchmark] = []
        if benchmark == "wavsep":
            possible_vulns["Acunetix"]["File inclusion"] = "SSRF"
        
        file = minidom.parse("results/Acunetix/" + benchmark + ".xml")
        types_alerts = file.getElementsByTagName('ReportItem')
        
        for alertitem in types_alerts:
            type_alert = alertitem.getElementsByTagName('Name')[0].firstChild.data
            if type_alert in list(possible_vulns["Acunetix"].keys())[:-2]: #temporariamente tirar csrf e cookies
                case = re.findall(patters[benchmark], alertitem.getElementsByTagName('Affects')[0].firstChild.data)[0]
                type_vuln = maps[benchmark][reverse_maps[benchmark][possible_vulns["Acunetix"][type_alert]]]
                #print(case)
                if case != "":
                    if type_vuln == cases[benchmark][case][0]:
                        cases[benchmark][case][2] = 1
                    else:
                        if case+"/"+type_vuln not in cases_fp[benchmark]:
                            cases_fp[benchmark].append(case+"/"+type_vuln)
                            notmakingsense_vulns[benchmark][type_vuln] += 1

        #results
        for case in cases[benchmark].values():
            #print(case)
            if case[1]==1:
                if case[1]==case[2]:
                    vulns[benchmark][case[0]][0]+=1
                else:
                    vulns[benchmark][case[0]][1]+=1
            else:
                if case[1]==case[2]:
                    vulns[benchmark][case[0]][3]+=1
                else:
                    vulns[benchmark][case[0]][2]+=1
        
    return cases, cases_fp, vulns, notmakingsense_vulns

def analyse_benchmark_wapiti(maps, reverse_maps, vulns, notmakingsense_vulns, cases, patters, benchmarks, possible_vulns):
    cases_fp = {}

    for benchmark in benchmarks:
        cases_fp[benchmark] = []
        if benchmark == "wavsep":
            possible_vulns["Wapiti"]["LFI"] = "SSRF"
        
        file = open("results/Wapiti/" + benchmark + ".txt", "r")
        
        for line in file.readlines():
            line_splitted = line.split(",")
            type_alert = line_splitted[1]
            if type_alert in list(possible_vulns["Wapiti"].keys()):
                case = line_splitted[0]
                type_vuln = maps[benchmark][reverse_maps[benchmark][possible_vulns["Wapiti"][type_alert]]]
                if case != "":
                    if type_vuln == cases[benchmark][case][0]:
                        cases[benchmark][case][2] = 1
                    else:
                        if case+"/"+type_vuln not in cases_fp[benchmark]:
                            cases_fp[benchmark].append(case+"/"+type_vuln)
                            notmakingsense_vulns[benchmark][type_vuln] += 1

        #results
        for case in cases[benchmark].values():
            #print(case)
            if case[1]==1:
                if case[1]==case[2]:
                    vulns[benchmark][case[0]][0]+=1
                else:
                    vulns[benchmark][case[0]][1]+=1
            else:
                if case[1]==case[2]:
                    vulns[benchmark][case[0]][3]+=1
                else:
                   vulns[benchmark][case[0]][2]+=1
        
    return cases, cases_fp, vulns, notmakingsense_vulns

def analyse_benchmark_owaspzap_plugins(maps, reverse_maps, vulns, notmakingsense_vulns, cases, patters, benchmarks, possible_vulns):
    cases_fp = {}

    for benchmark in benchmarks:
        cases_fp[benchmark] = []
        if benchmark == "wavsep":
            possible_vulns["OWASP ZAP Plugins"]["LFI"] = "SSRF"
        
        file = open("results/OWASP ZAP Plugins/" + benchmark + ".txt", "r")

        for line in file.readlines():
            line_splitted = line.split(",")
            type_alert = line_splitted[1]
            if type_alert in list(possible_vulns["OWASP ZAP Plugins"].keys()):
                case = line_splitted[0]
                type_vuln = maps[benchmark][reverse_maps[benchmark][possible_vulns["OWASP ZAP Plugins"][type_alert]]]
                if case != "":
                    if type_vuln == cases[benchmark][case][0]:
                        cases[benchmark][case][2] = 1
                    else:
                        if case+"/"+type_vuln not in cases_fp[benchmark]:
                            cases_fp[benchmark].append(case+"/"+type_vuln)
                            notmakingsense_vulns[benchmark][type_vuln] += 1

        #results
        for case in cases[benchmark].values():
            #print(case)
            if case[1]==1:
                if case[1]==case[2]:
                    vulns[benchmark][case[0]][0]+=1
                else:
                    vulns[benchmark][case[0]][1]+=1
            else:
                if case[1]==case[2]:
                    vulns[benchmark][case[0]][3]+=1
                else:
                    vulns[benchmark][case[0]][2]+=1
        
    return cases, cases_fp, vulns, notmakingsense_vulns


def analyse_results(list_vulnerabilities, list_tools, list_apps):
    xl = pd.read_excel('results/experience.xlsx', sheet_name=None)
    len_tools = len(list_tools)
    #res = len(xl)
    #print(res)
    #print(xl['Juice Shop'])
    cases = {}

    for app in list_apps:
        cases[app] = {}
        for i in range(len_tools):
            cases[app][list_tools[i]] = []

        for index, row in xl[app].iterrows():
            if row.iloc[3]==row.iloc[3]:#and row.iloc[3]=="Improper Output Neutralization for Logs":
                r = []
                for column, value in row.items():
                    r.append(str(value).replace('\n', ' ').replace('\r', ''))
                
                for i in range(len_tools):
                    if row.iloc[0]==row.iloc[0] and row.iloc[1]==row.iloc[1]:
                        #verification
                        if (len(r[1].split(","))!=len(r[4+i].split(","))):
                            #print(r[1].split(","))
                            print("Some parameteres don't have the same quantity")
                            print(index, row)
                            exit(1)

                        for num in r[4+i].split(","):
                            list_vulnerabilities[row.iloc[3]].incr_counting(list_tools[i], app, int(num), int(row.iloc[2]))
                            cases[app][list_tools[i]].append([row.iloc[3], int(row.iloc[2]), int(num)])

                    else:
                        if row.iloc[3]=="Bad Programming of Cookies":
                            #list_vulnerabilities[row.iloc[3]]
                            #print(r)
                            if (len(r[1].split(","))!=len(r[4+i].split(","))):
                                #print(r[1].split(","))
                                print("Some parameteres don't have the same quantity")
                                print(index, row)
                                exit(1)

                            for num in r[4+i].split(","):
                                list_vulnerabilities[row.iloc[3]].incr_counting(list_tools[i], app, int(num), int(row.iloc[2]))
                                cases[app][list_tools[i]].append([row.iloc[3], int(row.iloc[2]), int(num)])
                        else:
                            if row.iloc[3]!="CSRF":
                                #print(row)
                                list_vulnerabilities[row.iloc[3]].incr_counting(list_tools[i], app, int(r[4+i]), int(row.iloc[2]))
                                cases[app][list_tools[i]].append([row.iloc[3], int(row.iloc[2]), int(r[4+i])])
                            else:
                                elem_splitted = r[4+i].split("/")
                                list_vulnerabilities[row.iloc[3]].incr_csrf(list_tools[i], app, int(elem_splitted[0]), 0 if int(row.iloc[2]) else 2)
                                list_vulnerabilities[row.iloc[3]].incr_csrf(list_tools[i], app, int(elem_splitted[1]), 1 if int(row.iloc[2]) else 3)
                                    
                #print("==================")'''
    
    #for vuln in list_vulnerabilities.values():
    #    print(vuln.id)
    #    print(vuln)
    

    return list_vulnerabilities, cases
    
def analyse_results_fp(list_vulnerabilities, list_tools, list_apps):
    xl = pd.read_excel('results/experience_fp.xlsx', sheet_name=None)
    len_tools = len(list_tools)
    #res = len(xl)
    #print(res)
    #print(xl['Juice Shop'])
    cases = {}
    cases_total = {}
    vulns = {"Bypass Authorization": 0,
            "Path Traversal": 0,
            "Remote File Inclusion": 0,
            "CSRF": 0,
            "Transmission of Information in Cleartext": 0,
            "Untrusted/Invalid TLS certificate": 0,
            "Command Injection": 0,
            "SQL Injection": 0,
            "LDAP Injection": 0,
            "XSS": 0,
            "XPath Injection": 0,
            "HTTP Response Splitting": 0,
            "Exposed Improper Error Handling": 0,
            "Bad Security Design of Form Fields": 0,
            "Method Tampering": 0,
            "XXE": 0,
            "Bad Programming of Cookies": 0,
            "Hardcoded Secret": 0,
            "Vulnerable Outdated Component": 0,
            "Bypass Authentication": 0,
            "Brute Force Attack": 0,
            "Session Fixation": 0,
            "Insecure scope of Cookies": 0,
            "Insecure Deserialization": 0,
            "Improper Output Neutralization for Logs": 0,
            "SSRF": 0
            }

    for app in list_apps:
        i = 0
        cases[app] = {}
        cases[app][list_tools[i]] = []
        cs = []
        cases_total[app] = copy.deepcopy(vulns)

        for index, row in xl[app].iterrows():
            if row.iloc[0] == "END":
                break

            if row.iloc[0] != row.iloc[0] or row.iloc[0] == "URL":
                continue
            
            for parameter in row.iloc[2].split(","):
                if [row.iloc[3], parameter, row.iloc[0]] not in cs:
                    cases_total[app][row.iloc[3]]+=1
                    cs.append([row.iloc[3], parameter, row.iloc[0]])

        for index, row in xl[app].iterrows():
            if row.iloc[0] == "END":
                break

            if row.iloc[0] != row.iloc[0] or row.iloc[0] == "URL":
                if row.iloc[0] == "URL":
                    i += 1  
                    cases[app][list_tools[i]] = []
                    #cases[app][list_tools[i]] = copy.deepcopy(vulns)
                continue
            
            for parameter in row.iloc[2].split(","):
                list_vulnerabilities[row.iloc[3]].incr_counting_fp(list_tools[i], app)
                cases[app][list_tools[i]].append([row.iloc[3], parameter, row.iloc[0]])

    
    return list_vulnerabilities, cases, cases_total
        
def setup():
    list_tools = []
    list_vulns = []
    list_vulnerabilities = {}
    list_apps = []
    file_tools = open("setup/Tools.txt")
    file_vulns = open("setup/Vulnerabilities.txt")
    file_apps = open("setup/Applications.txt")
    possible_vulns = {}

    for line in file_tools.readlines():
        list_tools.append(line.strip("\n"))
        file = open("setup/possible_vulns/" + line.strip("\n") + "_possible_vulns.txt")
        dic = {}
        for vuln in file.readlines():
            splitted = vuln.split("#")
            dic[splitted[0]] = splitted[1].strip("\n")

        possible_vulns[line.strip("\n")] = dic

    for line in file_apps.readlines():
        list_apps.append(line.strip("\n"))

    for line in file_vulns.readlines():
        list_vulnerabilities[line.strip("\n")] = Vulnerability(line.strip("\n"), list_tools, list_apps)
        list_vulns.append(line.strip("\n"))

    return list_vulnerabilities, list_tools, list_apps, possible_vulns, list_vulns

def main():
    list_vulnerabilities, list_tools, list_apps, possible_vulns, list_vulns = setup()
    comb_2 = list(itertools.combinations(list_tools, 2))
    comb_3 = list(itertools.combinations(list_tools, 3))
    base_results = {}
    for v in list_vulns:
        base_results[v] = [0,0,0,0,0,0]

    list_vulnerabilities, cases = analyse_results(list_vulnerabilities, list_tools, list_apps)
    list_vulnerabilities, cases_fp, cases_fp_total = analyse_results_fp(list_vulnerabilities, list_tools, list_apps)
    overall_results = {}
    overall_results_comb2 = {}
    overall_results_comb3 = {}
    for t in list_tools:
        overall_results[t] = [0,0,0,0,0,0]
    for comb in comb_2:
        overall_results_comb2[comb] = [0,0,0,0,0,0]
    for comb in comb_3:
        overall_results_comb3[comb] = [0,0,0,0,0,0]

    latex = {}
    latex_results = {"Bypass Authorization": [0,0,0,0,0,0],
                   "Path Traversal": [0,0,0,0,0,0],
                   "Remote File Inclusion": [0,0,0,0,0,0],
                   "CSRF": [0,0,0,0,0,0],
                   "Transmission of Information in Cleartext": [0,0,0,0,0,0],
                   "Untrusted/Invalid TLS certificate": [0,0,0,0,0,0],
                   "Command Injection": [0,0,0,0,0,0],
                   "SQL Injection": [0,0,0,0,0,0],
                   "LDAP Injection": [0,0,0,0,0,0],
                   "XSS": [0,0,0,0,0,0],
                   "XPath Injection": [0,0,0,0,0,0],
                   "HTTP Response Splitting": [0,0,0,0,0,0],
                   "Exposed Improper Error Handling": [0,0,0,0,0,0],
                   "Bad Security Design of Form Fields": [0,0,0,0,0,0],
                   "Method Tampering": [0,0,0,0,0,0],
                   "XXE": [0,0,0,0,0,0],
                   "Bad Programming of Cookies": [0,0,0,0,0,0],
                   "Hardcoded Secret": [0,0,0,0,0,0],
                   "Vulnerable Outdated Component": [0,0,0,0,0,0],
                   "Bypass Authentication": [0,0,0,0,0,0],
                   "Brute Force Attack": [0,0,0,0,0,0],
                   "Session Fixation": [0,0,0,0,0,0],
                   "Insecure scope of Cookies": [0,0,0,0,0,0],
                   "Insecure Deserialization": [0,0,0,0,0,0],
                   "Improper Output Neutralization for Logs": [0,0,0,0,0,0],
                   "SSRF": [0,0,0,0,0,0]
                  }

    latex_categories = {"A1 Broken Access Control": ["Bypass Authorization", "Path Traversal", "Remote File Inclusion", "CSRF"],
                        "A2 Cryptographic Failure": ["Transmission of Information in Cleartext", "Untrusted/Invalid TLS certificate"],
                        "A3 Injection": ["Command Injection", "SQL Injection", "LDAP Injection", "XSS", "XPath Injection", "HTTP Response Splitting"],
                        "A4 Insecure Design": ["Exposed Improper Error Handling", "Bad Security Design of Form Fields", "Method Tampering"],
                        "A5 Security Misconfiguration": ["XXE", "Bad Programming of Cookies", "Hardcoded Secret"],
                        "A6 Vulnerable and Outdated Components": ["Vulnerable Outdated Component"],
                        "A7 Identification and Authentication Failures": ["Bypass Authentication", "Brute Force Attack", "Session Fixation"],
                        "A8 Software and Data Integrity Failures": ["Insecure scope of Cookies", "Insecure Deserialization"],
                        "A9 Security Logging and Monitoring Failures": ["Improper Output Neutralization for Logs"],
                        "A10 Server-Side Request Forgery": ["SSRF"],
                        }

    latex_vulns = {"Bypass Authorization":"Bypassing Authorization",
                     "Path Traversal":"Path Traversal",
                     "Remote File Inclusion":"Remote File Inclusion",
                     "CSRF": "Cross-Site Request Forgery",
                     "Transmission of Information in Cleartext": "Transmission of Information in Cleartext",
                     "Untrusted/Invalid TLS certificate": "Untrusted/Invalid TLS Certificate",
                     "Command Injection": "OS Command Injection", 
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


    tool_vulns = {}
    vulns_quant = {}
    for t in list_tools:
        tool_vulns[t] = {}
        for v in list_vulnerabilities.keys(): 
            tool_vulns[t][v] = [0,0,0,0]
            vulns_quant[v] = 0

        tool_vulns[t]["NaN"] = [0,0,0,0]
        vulns_quant["NaN"] = 0

    vulning = {}
    metrics = {}
    for v in list_vulnerabilities:
        vulning[v] = {}
        metrics[v] = {}
        for t in list_tools:
            vulning[v][t] = [0,0,0,0,0,0] #tp, fn, fp, tn, fpfp, tnfp
            metrics[v][t] = [0,0,0,0,0,0] #recall, recall*informedness, f-measure, markedness, precision

    #SINGULAR
    print("###################################################################################################")
    print("############################################ SINGULAR ############################################")
    print("###################################################################################################")
    for a in list_apps:
        latex[a] = {}
        for t in list_tools:
            latex[a][t] = copy.deepcopy(latex_results)

        print("========================= " + str(a) + " =========================")
        for t in list_tools:
            tp, fn, fp, tn, fpfp, fptn = 0, 0, 0, 0, 0, 0
            results = copy.deepcopy(base_results)   
            #MAKING SENSE
            for i in range(len(cases[a][t])):
                if cases[a][t][i][1] == 1:
                    if cases[a][t][i][1] == cases[a][t][i][2]:
                        results[cases[a][t][i][0]][0]+=1
                        tp += 1
                    else:
                        results[cases[a][t][i][0]][1]+=1
                        fn += 1
                else:
                    if cases[a][t][i][1] == cases[a][t][i][2]:
                        results[cases[a][t][i][0]][3]+=1
                        tn += 1
                    else:
                        results[cases[a][t][i][0]][2]+=1
                        fp += 1

            #CSRF
            results["CSRF"][0] = list_vulnerabilities["CSRF"].tools[t][a].counting[0]; tp += list_vulnerabilities["CSRF"].tools[t][a].counting[0]
            results["CSRF"][1] = list_vulnerabilities["CSRF"].tools[t][a].counting[1]-list_vulnerabilities["CSRF"].tools[t][a].counting[0]; fn += results["CSRF"][1] 
            results["CSRF"][2] = list_vulnerabilities["CSRF"].tools[t][a].counting[2]; fp += list_vulnerabilities["CSRF"].tools[t][a].counting[2]
            results["CSRF"][3] = list_vulnerabilities["CSRF"].tools[t][a].counting[3]-list_vulnerabilities["CSRF"].tools[t][a].counting[2]; tn += results["CSRF"][3] 

            #NOT MAKING SENSE - FALSE POSITIVES NOT INCLUDED BEFORE
            for i in range(len(cases_fp[a][t])):
                results[cases_fp[a][t][i][0]][4]+=1
                fpfp += 1
        
            print("========================= " + str(t) + " =========================")
            for k, v, v_fp in zip(results.keys(), results.values(), [0]*len(results)):
                tool_vulns[t][k][0] += v[0]
                tool_vulns[t][k][1] += v[1]
                tool_vulns[t][k][2] += v[2]
                tool_vulns[t][k][3] += v[3]

                vulning[k][t][0] += v[0]
                vulning[k][t][1] += v[1]
                vulning[k][t][2] += v[2]
                vulning[k][t][3] += v[3]
                vulning[k][t][4] += v[4]
                vulning[k][t][5] += cases_fp_total[a][k]-v[4]

                latex[a][t][k][0] += v[0]
                latex[a][t][k][1] += v[1]
                latex[a][t][k][2] += v[2]
                latex[a][t][k][3] += v[3]
                latex[a][t][k][4] += v[4]
                latex[a][t][k][5] += cases_fp_total[a][k]-v[4]

                print(k + ":", "TP:" + str(v[0]) + "|", "FN:" + str(v[1]) + "|", "FP:" + str(v[2]+v[4]) + "(" + str(v[4]) + ")|", "TN:" + str(v[3]+cases_fp_total[a][k]-v[4]) + "(" + str(cases_fp_total[a][k]-v[4]) + ")|")
            fptn = (sum([vk for vk in cases_fp_total[a].values()]) - fpfp)
            print("[" + t + "]:", "TP:" + str(tp) + "|", "FN:" + str(fn) + "|", "FP:" + str(fp+fpfp) + "(" + str(fpfp) + ")|", "TN:" + str(tn+fptn) + "(" + str(fptn) + ")|")
            overall_results[t][0] += tp; overall_results[t][1] += fn; overall_results[t][2] += fp; overall_results[t][3] += tn; overall_results[t][4] += fpfp; overall_results[t][5] += fptn
            print()
        print()
        print()

    #COMBINATIONS 2
    print("###################################################################################################")
    print("######################################### COMBINATIONS 2 #########################################")
    print("###################################################################################################")
    for a in list_apps:
        print("========================= " + str(a) + " =========================")
        for comb in comb_2:
            tp, fn, fp, tn, fpfp, fptn = 0, 0, 0, 0, 0, 0
            results = copy.deepcopy(base_results)   
            #MAKING SENSE
            for i in range(len(cases[a][t])):
                if cases[a][comb[0]][i][1] == 1:
                    if cases[a][comb[0]][i][1] == cases[a][comb[0]][i][2] | cases[a][comb[1]][i][2]:
                        results[cases[a][comb[0]][i][0]][0]+=1
                        tp+=1
                    else:
                        results[cases[a][comb[0]][i][0]][1]+=1
                        fn+=1
                else:
                    if cases[a][comb[0]][i][1] == cases[a][comb[0]][i][2] | cases[a][comb[1]][i][2]:
                        results[cases[a][comb[0]][i][0]][3]+=1
                        tn+=1
                    else:
                        results[cases[a][comb[0]][i][0]][2]+=1
                        fp+=1

            #CSRF
            results["CSRF"][0] = list_vulnerabilities["CSRF"].tools[comb[0]][a].counting[0] | list_vulnerabilities["CSRF"].tools[comb[1]][a].counting[0] if list_vulnerabilities["CSRF"].tools[comb[0]][a].counting[0] | list_vulnerabilities["CSRF"].tools[comb[1]][a].counting[0] < list_vulnerabilities["CSRF"].tools[comb[0]][a].counting[1] else list_vulnerabilities["CSRF"].tools[comb[0]][a].counting[1]
            tp += results["CSRF"][0]
            results["CSRF"][1] = list_vulnerabilities["CSRF"].tools[comb[0]][a].counting[1]-results["CSRF"][0]
            fn += results["CSRF"][1] 
            results["CSRF"][2] = list_vulnerabilities["CSRF"].tools[comb[0]][a].counting[2] | list_vulnerabilities["CSRF"].tools[comb[1]][a].counting[2] if list_vulnerabilities["CSRF"].tools[comb[0]][a].counting[2] | list_vulnerabilities["CSRF"].tools[comb[1]][a].counting[2] < list_vulnerabilities["CSRF"].tools[comb[0]][a].counting[3] else list_vulnerabilities["CSRF"].tools[comb[0]][a].counting[3]
            fp += results["CSRF"][2] 
            results["CSRF"][3] = list_vulnerabilities["CSRF"].tools[comb[0]][a].counting[3]-results["CSRF"][2]
            tn += results["CSRF"][3] 
                
            #NOT MAKING SENSE - FALSE POSITIVES NOT INCLUDED BEFORE
            comb_list = list(set(tuple(i) for i in cases_fp[a][comb[0]]) | set(tuple(i) for i in cases_fp[a][comb[1]]))
            for i in range(len(comb_list)):
                results[comb_list[i][0]][4]+=1
                fpfp += 1

            print("========================= " + str(comb) + " =========================")
            for k, v, v_fp in zip(results.keys(), results.values(), [0]*len(results)):
                print(k + ":", "TP:" + str(v[0]) + "|", "FN:" + str(v[1]) + "|", "FP:" + str(v[2]+v[4]) + "(" + str(v[4]) + ")|", "TN:" + str(v[3]+cases_fp_total[a][k]-v[4]) + "(" + str(cases_fp_total[a][k]-v[4]) + ")|")
            fptn = (sum([vk for vk in cases_fp_total[a].values()]) - fpfp)
            #print("AAAA", fpfp, fptn)
            print("[" + str(comb) + "]:", "TP:" + str(tp) + "|", "FN:" + str(fn) + "|", "FP:" + str(fp+fpfp) + "(" + str(fpfp) + ")|", "TN:" + str(tn+fptn) + "(" + str(fptn) + ")|")
            overall_results_comb2[comb][0] += tp; overall_results_comb2[comb][1] += fn; overall_results_comb2[comb][2] += fp; overall_results_comb2[comb][3] += tn; overall_results_comb2[comb][4] += fpfp; overall_results_comb2[comb][5] += fptn
            print()
        print()
        print()

    #COMBINATIONS 3
    print("###################################################################################################")
    print("######################################### COMBINATIONS 3 #########################################")
    print("###################################################################################################")
    for a in list_apps:
        print("========================= " + str(a) + " =========================")
        for comb in comb_3:
            tp, fn, fp, tn, fpfp = 0, 0, 0, 0, 0
            results = copy.deepcopy(base_results)   
            #MAKING SENSE
            for i in range(len(cases[a][t])):
                if cases[a][comb[0]][i][1] == 1:
                    if cases[a][comb[0]][i][1] == cases[a][comb[0]][i][2] | cases[a][comb[1]][i][2] | cases[a][comb[2]][i][2]:
                        results[cases[a][comb[0]][i][0]][0]+=1
                        tp+=1
                    else:
                        results[cases[a][comb[0]][i][0]][1]+=1
                        fn+=1
                else:
                    if cases[a][comb[0]][i][1] == cases[a][comb[0]][i][2] | cases[a][comb[1]][i][2] | cases[a][comb[2]][i][2]:
                        results[cases[a][comb[0]][i][0]][3]+=1
                        tn+=1
                    else:
                        results[cases[a][comb[0]][i][0]][2]+=1
                        fp+=1
                
            #CSRF
            results["CSRF"][0] = list_vulnerabilities["CSRF"].tools[comb[0]][a].counting[0] | list_vulnerabilities["CSRF"].tools[comb[1]][a].counting[0] | list_vulnerabilities["CSRF"].tools[comb[2]][a].counting[0] if list_vulnerabilities["CSRF"].tools[comb[0]][a].counting[0] | list_vulnerabilities["CSRF"].tools[comb[1]][a].counting[0] | list_vulnerabilities["CSRF"].tools[comb[2]][a].counting[0] < list_vulnerabilities["CSRF"].tools[t][a].counting[1] else list_vulnerabilities["CSRF"].tools[t][a].counting[1]
            tp += results["CSRF"][0]
            results["CSRF"][1] = list_vulnerabilities["CSRF"].tools[t][a].counting[1]-results["CSRF"][0]
            fn += results["CSRF"][1] 
            results["CSRF"][2] = list_vulnerabilities["CSRF"].tools[comb[0]][a].counting[2] | list_vulnerabilities["CSRF"].tools[comb[1]][a].counting[2] | list_vulnerabilities["CSRF"].tools[comb[2]][a].counting[2] if list_vulnerabilities["CSRF"].tools[comb[0]][a].counting[2] | list_vulnerabilities["CSRF"].tools[comb[1]][a].counting[2] | list_vulnerabilities["CSRF"].tools[comb[2]][a].counting[2] < list_vulnerabilities["CSRF"].tools[t][a].counting[3] else list_vulnerabilities["CSRF"].tools[t][a].counting[3]
            fp += results["CSRF"][2] 
            results["CSRF"][3] = list_vulnerabilities["CSRF"].tools[t][a].counting[3]-results["CSRF"][2]
            tn += results["CSRF"][3] 

            #NOT MAKING SENSE - FALSE POSITIVES NOT INCLUDED BEFORE
            comb_list = list(set(tuple(i) for i in cases_fp[a][comb[0]]) | set(tuple(i) for i in cases_fp[a][comb[1]]) | set(tuple(i) for i in cases_fp[a][comb[2]]))
            for i in range(len(comb_list)):
                results[comb_list[i][0]][4]+=1
                fpfp += 1

            print("========================= " + str(comb) + " =========================")
            for k, v, v_fp in zip(results.keys(), results.values(), [0]*len(results)):
                print(k + ":", "TP:" + str(v[0]) + "|", "FN:" + str(v[1]) + "|", "FP:" + str(v[2]+v[4]) + "(" + str(v[4]) + ")|", "TN:" + str(v[3]+cases_fp_total[a][k]-v[4]) + "(" + str(cases_fp_total[a][k]-v[4]) + ")|")
            fptn = (sum([vk for vk in cases_fp_total[a].values()]) - fpfp)
            #print("AAAA", fpfp, fptn)
            print("[" + str(comb) + "]:", "TP:" + str(tp) + "|", "FN:" + str(fn) + "|", "FP:" + str(fp+fpfp) + "(" + str(fpfp) + ")|", "TN:" + str(tn+fptn) + "(" + str(fptn) + ")|")
            overall_results_comb3[comb][0] += tp; overall_results_comb3[comb][1] += fn; overall_results_comb3[comb][2] += fp; overall_results_comb3[comb][3] += tn; overall_results_comb3[comb][4] += fpfp; overall_results_comb3[comb][5] += fptn
            print()
        print()
        print()
    
    if O_ALL == True:
        #OVERALL
        print("###################################################################################################")
        print("######################################### OVERALL RESULTS #########################################")
        print("###################################################################################################")
        for t, res in overall_results.items():
            print("[" + str(t) + "]:", "TP:" + str(res[0]) + "|", "FN:" + str(res[1]) + "|", "FP:" + str(res[2]+res[4]) + "(" + str(res[4]) + ")|", "TN:" + str(res[3]+res[5]) + "(" + str(res[5]) + ")|")
        print()

        for comb, res in overall_results_comb2.items():
            print("[" + str(comb) + "]:", "TP:" + str(res[0]) + "|", "FN:" + str(res[1]) + "|", "FP:" + str(res[2]+res[4]) + "(" + str(res[4]) + ")|", "TN:" + str(res[3]+res[5]) + "(" + str(res[5]) + ")|")
        print()

        for comb, res in overall_results_comb3.items():
            print("[" + str(comb) + "]:", "TP:" + str(res[0]) + "|", "FN:" + str(res[1]) + "|", "FP:" + str(res[2]+res[4]) + "(" + str(res[4]) + ")|", "TN:" + str(res[3]+res[5]) + "(" + str(res[5]) + ")|")
        print()

    print()
    print()
    print()
    print()
    print("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    print()
    print()
    print()
    print()

    tool_vulns, vulns_quant, vulning, results = analyse_benchmarks(possible_vulns, list_tools, tool_vulns, vulns_quant, vulning)
    

    for t in list_tools:
        print("-----", t, "-----")
        tpr = []
        fpr = []
        for v in list(list_vulnerabilities.keys())+["NaN"]:
            #print(v + ": " + str(tool_vulns[t][v]))
            tpr.append((v, tool_vulns[t][v][0]/(tool_vulns[t][v][0]+tool_vulns[t][v][1]) if (tool_vulns[t][v][0]+tool_vulns[t][v][1]) > 0 else 0 ))
            fpr.append((v, tool_vulns[t][v][2]/(tool_vulns[t][v][2]+tool_vulns[t][v][3]) if (tool_vulns[t][v][2]+tool_vulns[t][v][3]) > 0 else 0 ))
        
        tpr = sorted(tpr, key=lambda x: -x[1])
        fpr = sorted(fpr, key=lambda x: -x[1])

        for t in tpr:
            print(t[0], t[1])

        print()
        
        for f in fpr:
            print(f[0], f[1])

        print()
        print()

    #WEIGHTS
    wghts = weights(vulning, metrics)        
    analyse_results_weighted(wghts, list_apps, list_tools, comb_2, base_results, cases, results, list_vulnerabilities)

    #LATEX
    LATEX = open("LATEX_geral_apps.txt", "w")
    t_1st = ["OWASP ZAP", "BurpSuite", "Iron Wasp"]
    t_2nd = ["Acunetix", "Wapiti", "OWASP ZAP Plugins"]
    for app in list_apps:
        LATEX.write("\\textbf{\\large Results obtained in " + app + "}\\newline\n\n")

        LATEX.write("\\begin{tiny}\n")
        LATEX.write("\\captionsetup{font=footnotesize}\n")
        LATEX.write("\\centering\n")
        LATEX.write("\\setlength{\\tabcolsep}{3pt}\n")
        LATEX.write("\\begin{longtable}{*{1}{|wc{0.1in}|m{1.55in}|} *{3}{>{\\columncolor{anti-flashwhite}}wc{0.35cm}|}")

        flg = 0
        for t in t_1st:
            LATEX.write(" *{4}{" + ("" if flg == 0 else ">{\\columncolor{anti-flashwhite}}") + "wc{0.35cm}|}")
            flg ^=1

        LATEX.write("}\n")

        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightgray}\\multicolumn{5}{|c|}{Vulnerability} & \\multicolumn{" + str(4*len(t_1st)) + "}{c|}{Tools} \\\\\n")
        LATEX.write("\\hline\n")
        
        LATEX.write("\\rowcolor{lightgray} ID & \\multicolumn{1}{c}{Name} &  \\multicolumn{3}{|c|}{Total}")
        for t in t_1st:
            LATEX.write(" & \\multicolumn{4}{c|}{" + t + "}")

        LATEX.write("\\\\\n\\hline\n")
        
        for c, vulns in latex_categories.items():
            c_splitted = c.split(" ")
            LATEX.write("\\rowcolor{lightlightgray} " + c_splitted[0] + " & " + " ".join(c_splitted[1:]) + " & P & N & FPFP")
            LATEX.write(" & TP & FN & FP & TN"*len(t_1st))
            
            LATEX.write("\\\\\n")
            LATEX.write("\\hline"+ "\n")

            for k in vulns:
                LATEX.write("\\multicolumn{2}{|m{1.7in}|}{" + latex_vulns[k] + "} & " +  str(latex[app]["OWASP ZAP"][k][0]+latex[app]["OWASP ZAP"][k][1]) +  " & " + str(latex[app]["OWASP ZAP"][k][2]+latex[app]["OWASP ZAP"][k][3]) +  " & " + str(latex[app]["OWASP ZAP"][k][4]+latex[app]["OWASP ZAP"][k][5]))
                for t in t_1st:
                    LATEX.write(" & " + str(latex[app][t][k][0]) + " & " + str(latex[app][t][k][1]) + " & " + str(latex[app][t][k][2]+latex[app][t][k][4]) + " & " + str(latex[app][t][k][3]+latex[app][t][k][5]))

                LATEX.write("\\\\\n")
                LATEX.write("\\hline"+ "\n")
            LATEX.write("\n")

        LATEX.write("\\caption{DAST tools output in relation to " + app +  " - Part1}\n")
        LATEX.write("\\label{table:DAST tools output in relation to " + app +  " - Part1}\n")
        LATEX.write("\\end{longtable}\n")
        LATEX.write("\\end{tiny}\n")
        
        LATEX.write("\n\n\n")
        
        LATEX.write("\\begin{tiny}\n")
        LATEX.write("\\captionsetup{font=footnotesize}\n")
        LATEX.write("\\centering\n")
        LATEX.write("\\setlength{\\tabcolsep}{3pt}\n")
        LATEX.write("\\begin{longtable}{*{1}{|wc{0.1in}|m{1.55in}|} *{3}{>{\\columncolor{anti-flashwhite}}wc{0.35cm}|}")

        flg = 0
        for t in t_2nd:
            LATEX.write(" *{4}{" + ("" if flg == 0 else ">{\\columncolor{anti-flashwhite}}") + "wc{0.35cm}|}")
            flg ^=1

        LATEX.write("}\n")

        LATEX.write("\\hline\n")
        LATEX.write("\\rowcolor{lightgray}\\multicolumn{5}{|c|}{Vulnerability} & \\multicolumn{" + str(4*len(t_2nd)) + "}{c|}{Tools} \\\\\n")
        LATEX.write("\\hline\n")
        
        LATEX.write("\\rowcolor{lightgray} ID & \\multicolumn{1}{c}{Name} &  \\multicolumn{3}{|c|}{Total}")
        for t in t_2nd:
            LATEX.write(" & \\multicolumn{4}{c|}{" + t + "}")

        LATEX.write("\\\\\n\\hline\n")
        
        for c, vulns in latex_categories.items():
            c_splitted = c.split(" ")
            LATEX.write("\\rowcolor{lightlightgray} " + c_splitted[0] + " & " + " ".join(c_splitted[1:]) + " & P & N & FPFP")
            LATEX.write(" & TP & FN & FP & TN"*len(t_2nd))
            
            LATEX.write("\\\\\n")
            LATEX.write("\\hline"+ "\n")

            for k in vulns:
                LATEX.write("\\multicolumn{2}{|m{1.7in}|}{" + latex_vulns[k] + "} & " +  str(latex[app]["OWASP ZAP"][k][0]+latex[app]["OWASP ZAP"][k][1]) +  " & " + str(latex[app]["OWASP ZAP"][k][2]+latex[app]["OWASP ZAP"][k][3]) +  " & " + str(latex[app]["OWASP ZAP"][k][4]+latex[app]["OWASP ZAP"][k][5]))
                for t in t_2nd:
                    LATEX.write(" & " + str(latex[app][t][k][0]) + " & " + str(latex[app][t][k][1]) + " & " + str(latex[app][t][k][2]+latex[app][t][k][4]) + " & " + str(latex[app][t][k][3]+latex[app][t][k][5]))

                LATEX.write("\\\\\n")
                LATEX.write("\\hline"+ "\n")
            LATEX.write("\n")

        LATEX.write("\\caption{DAST tools output in relation to " + app +  " - Part2}\n")
        LATEX.write("\\label{table:DAST tools output in relation to " + app +  " - Part2}\n")
        LATEX.write("\\end{longtable}\n")
        LATEX.write("\\end{tiny}\n")
        
        LATEX.write("\n\n")
        LATEX.write("\\newpage")

        LATEX.write("\n\n\n")
    


if __name__=="__main__":
    main()

    