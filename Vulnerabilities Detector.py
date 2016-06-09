__author__ = 'cyankw'
import re
import urllib.request
from multiprocessing import Pool
import time

strtime = time.clock() #计时器启动

def getHtml (url): #用于读取网页源代码
    page = urllib.request.urlopen(url)
    html = page.read()
    return html

global year
global keywd

def getCVE(html): #对读取的网页源代码使用正则表达式进行筛选
    reg = r'/\bCVE-%s-\b\d{1,4}'%(year)
    CVEs = re.compile(reg)
    CVElist = re.findall(CVEs,html)
    Xmax = len(CVElist)
    x=0
    CVElist2=[]
    while x < Xmax: #去除每个被正则表达式匹配出的结果的第一个字符“/”
        CVElist2.append(CVElist[x][1:])
        x=x+1
    return CVElist2

def getKWD(html): #关键词词频统计，统计网页中keywd出现次数，（每出现一次，就记录一次）
    reg = r'/\b<em>\b%s\b</em>\b'%(keywd)
    KWDs = re.compile(reg)
    KWDlist = re.findall(KWDs,html)
    #print(KWDlist)
    return KWDlist



if __name__=='__main__':
    i=1
    getCVE2=[]
    print('Vulnerabilities Detector Started')
    year = input('Year  ')
    times = int(input('Result Number    '))
    poolnum = int(input('Pool Numbers   '))
    print('clawler started...')
    p = Pool(poolnum) #使用进程池调用的进程数量

    rangmax = times
    m=0
    gd=0
    numb = 0
    while numb<times:
        html = getHtml("http://cve.scap.org.cn/cve_list.php?action=cvss&floor=9.5&ceil=10&p=%u"%(i)).decode('utf-8') #从指定网页读取源代码
        i = i + 1
        getCVE2 = list(set(getCVE(html))) #使用getCVE（）函数进行数据筛选，去除重复项目，并记录结果到列表getCVE2中
        #print(getCVE2)
        f=0
        ln=len(getCVE2)
        while f<ln :
            if numb == times:
                break
            getKY = []
            keywd = getCVE2[f] #从二级列表getCVE2中获取到的次级元素中迭代当前元素（列表）中的子元素
            html = getHtml("http://www.baidu.com/baidu?wd=%s" % (keywd)).decode('utf-8') #将指定关键词进行百度搜索
            getKY.append((getKWD(html))) #使用getKWD（）进行词频统计

            url = "http://www.baidu.com/baidu?wd=%s" %(keywd)#用于打印固定文本
            #print(getKY)
            if len(getKY) >= 5: #对词频结果给出其价值
                GG='EXCELLENT!!!! %s'%(url)
                gd = gd + 1
            elif len(getKY) >= 3:
                GG='GOOD!!! %s'%(url)
            elif len(getKY) > 0:
                GG='simple'
            elif len(getKY) == 0:
                GG='-----'
            print(numb,keywd,len(getKY),GG),
            f=f+1
            numb=numb+1
        m = m + 1
    p.close()
    p.join()

    print('------------------------------------')
    print('Vulnerabilities Detect Completed')
    fintime = time.clock() #计时器结束
    print('Program running time %fs'%(fintime-strtime))
    print('We detected %u targets through %u websites, %u of them is valuable'%(numb,m,gd))