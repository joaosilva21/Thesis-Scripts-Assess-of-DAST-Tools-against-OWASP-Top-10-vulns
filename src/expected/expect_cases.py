
import glob, re

def main():
    for file in glob.glob('active/**/**/**/Case**.jsp', recursive=False)+glob.glob('active/**/**/Case**.jsp', recursive=False):
        splitted = file.split("\\")
        #print(splitted)
        if re.match(".*FalsePositives.*", splitted[2]):
            print(splitted[-2] + "/" + splitted[-1] + "," + splitted[1] + "," + "FALSE,")
        else:
            print(splitted[-2] + "/" + splitted[-1] + "," + splitted[1] + "," + "TRUE,")



if __name__=="__main__":
    main()