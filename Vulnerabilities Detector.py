_author_ = 'cyankw'
import re
import urllib.request
from multiprocessing import Pool
import time

strtime = time.clock() #计时器启动

def getHtml (url): #用于读取网页源代码
    page = urllib.request.urlopen(url)
    html = page.read()
    return html

def getCVE(html): #对读取的网页源代码使用正则表达式进行筛选
    reg = r'/\bCVE-2016-\b\d{1,4}'
    CVEs = re.compile(reg)
    CVElist = re.findall(CVEs,html)
    Xmax = len(CVElist)
    x=0
    CVElist2=[]
    while x < Xmax: #去除每个被正则表达式匹配出的结果的第一个字符“/”
        CVElist2.append(CVElist[x][1:])
        x=x+1
    return CVElist2

global keywd

def getKWD(html): #关键词词频统计，统计网页中keywd出现次数，（每出现一次，就记录一次）
    reg = r'/\b<em>cve-2016-\b\d{1,4}\b</em>\b'
    KWDs = re.compile(reg)
    KWDlist = re.findall(KWDs,html)
    return KWDlist

if __name__=='__main__':
    i=1
    getCVE2=[]
    print('Vulnerabilities Detector Started')
    p = Pool(4) #使用进程池调用的进程数量
    while i<=5: #要求爬取的次数，应与line43的值保持一致
        html = getHtml("http://cve.scap.org.cn/cve_list.php?action=cvss&floor=9.5&ceil=10&p=%u"%(i)).decode('utf-8') #从指定网页读取源代码
        i=i+1
        getCVE2.append(list(set(getCVE(html)))) #使用getCVE（）函数进行数据筛选，去除重复项目，并记录结果到列表getCVE2中
    p.close()
    p.join()
    #print(getCVE2)
    rangmax = 5 #要求爬取的次数，应与line36的值保持一致
    m=0
    c=0
    gd=0
    while m<rangmax : #在二级列表getCVE2中迭代次级元素（列表）
        """
        二级列表getCVE2样例：
        [[1,2,5],[66,70,24],[34,24,88],[0,22],[55,9]]
        """
        f=0
        ln = len(getCVE2[m])-1
        getKY = []
        GG='default'
        while f<ln :
            keywd = getCVE2[m][f] #从二级列表getCVE2中获取到的次级元素中迭代当前元素（列表）中的子元素
            html = getHtml("http://www.baidu.com/baidu?wd=%s" % (keywd)).decode('utf-8') #将指定关键词进行百度搜索
            getKY.append((getKWD(html))) #使用getKWD（）进行词频统计
            url = "http://www.baidu.com/baidu?wd=%s" %(keywd)
            if len(getKY) >= 5: #对词频结果给出其价值
                GG='EXCELLENT!!!! %s'%(url)
                gd = gd + 1
            elif len(getKY) >= 3:
                GG='GOOD!!! %s'%(url)
            elif len(getKY) > 0:
                GG='simple'
            elif len(getKY) == 0:
                GG='-----'
            print(c,keywd,len(getKY),GG),
            f=f+1
            c=c+1
        m=m+1
    print('------------------------------------')
    print('Vulnerabilities Detect Completed')
    fintime = time.clock() #计时器结束
    print('program running time %fs'%(fintime-strtime))
    print('We detected %u targets, %u of them is valuable'%(c,gd))

