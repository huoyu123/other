#!/usr/bin/env python
# -*- coding: gbk -*-
# @Time    : 2016/12/30 11:38
# @Author  : chenguangyu
# @Email    : chenguangu@xueleyun.com
# @File    : WmsDeplpy.py
# @Software: PyCharm


import zipfile
import os
import shutil
import logging
import time
import paramiko
import sys
import re
import subprocess
import codecs
import locale


def func_time(func):
    def _wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        times = time.time() - start
        msg = '%s run time: %s' % (func.__name__, times)
        print(msg)
        logging.info(msg)
        return result

    return _wrapper


@func_time
def sftpupfile(host, port, user, password, remotefile, localfile):
    t = paramiko.Transport((host, port))
    t.connect(username=user, password=password)
    sftp = paramiko.SFTPClient.from_transport(t)
    try:
        sftp.put(localfile,remotefile)
    except Exception, e:
        logging.error('ERROR: sftp_get - %s' % e)
        print('ERROR: sftp_get - %s' % e)
        return False
    t.close()
    return True


def fetch_branch(sourceBranch):
    path = "D:/jenkins/workspace/wms"
    branch = sourceBranch.split('/')[-1]
    os.chdir(path)
    cmd = "git checkout master"
    result = os.popen(cmd).readlines()
    logging.info(result)
    print(result)
    cmd = "git pull"
    result = os.popen(cmd).readlines()
    print(result)
    logging.info(result)
    cmd = 'git branch'
    result = os.popen(cmd).readlines()
    if str(result).find(branch) != -1:
        cmd = "git checkout {0}".format(branch)
        result = os.popen(cmd).readlines()
        print(result)
        logging.info(result)
        cmd = "git pull"
    else:
        cmd = "git checkout -b {0} {1}".format(branch, sourceBranch)
    result = os.popen(cmd).readlines()
    print(result)
    cmd = "git pull origin master"
    result = os.popen(cmd).readlines()
    print(result)
    logging.info(result)


def ext_file(filelist):
    extfile = ['\\Configs\\','\\Configs\\Bose.XueLe.WMS.Dal.config','\\Configs\\Bose.Xuele.WMS.Bll.config', 'Bose.XueLe.WMS\\Web.config', 'Bose.XueLe.WMS\\Web.Release.config']
    for ext in extfile:
        for file in filelist:
            if file.find(ext) != -1:
                print("remove: " + file)
                filelist.remove(file)
    return filelist

@func_time
def zip_dir(dirname, zipfilename):
    filelist = []
    if os.path.exists(zipfilename):
        os.remove(zipfilename)
    if os.path.isfile(dirname):
        filelist.append(dirname)
    else:
        for root, dirs, files in os.walk(dirname):
            for name in files:
                filelist.append(os.path.join(root, name))
    
    filelist = ext_file(filelist)
    zf = zipfile.ZipFile(zipfilename, "w", zipfile.zlib.DEFLATED)
    for tar in filelist:
        arcname = tar
        # arcname = tar[len(dirname):]
        # print arcname
        zf.write(tar, arcname)
    print("zip file success!")
    logging.info("zip file success")
    zf.close()

@func_time
def zipExtract(zfilename, temppath):
    zfile = zipfile.ZipFile(zfilename)
    try:
        zfile.extractall(path=temppath)
    except IOError, e:
        msg = "文件 %s 解压错误: %s" % (zfilename, e)
        print(msg)
        logging.error(msg)
        return False
    return True

def backupFiles(sourcePath, destfile):
    try:
        f = zipfile.ZipFile(destfile,"w",zipfile.ZIP_DEFLATED)
        for dirpath, dirnames, filenames in os.walk(sourcePath):
            for filename in filenames:
                f.write(os.path.join(dirpath,filename))
        f.close()
        return True
    except Exception,e:
        msg = "目录 %s 备份失败: %s" % (sourcePath, e)
        logging.error(msg)
        print(msg)
        f.close()
        return False


# @func_time
def updateFiles(sourceDir, targetDir):
    for file in os.listdir(sourceDir):
        sourceFile = os.path.join(sourceDir, file)
        targetFile = os.path.join(targetDir, file)
        if os.path.isfile(sourceFile):
            try:
                shutil.copy2(sourceFile, targetFile)
            except Exception, e:
                print("拷备文件 %s 到目标 %s 失败 %s" % (sourceFile, targetFile, e))
                logging.error("拷备文件 %s 到目标 %s 失败 %s" % (sourceFile, targetFile, e))
                return False
        elif os.path.isdir(sourceFile):
            if os.path.exists(targetFile):
                updateFiles(sourceFile, targetFile)
            else:
                try:
                    shutil.copytree(sourceFile, targetFile)
                except Exception, e:
                    print("拷备目录文件 %s 到目标 %s 失败 %s" % (sourceFile, targetFile, e))
                    logging.error("拷备目录文件 %s 到目标 %s 失败 %s" % (sourceFile, targetFile, e))
                    return False
        else:
            continue
    return True


@func_time
def checkUpdate(zfilename, path):
    zfile = zipfile.ZipFile(zfilename)
    successlist = []
    failelist = []
    for zf in zfile.infolist():
        if not zf.filename.endswith('/'):
            dfile = zf.filename.replace('Bose.XueLe.WMS/', '')
            destfile = os.path.join(path, dfile)
            if os.path.isfile(destfile) and (zf.file_size == os.path.getsize(destfile)):
                pass
                # successlist.append(zf.filename)
            else:
                failelist.append(zf.filename)
    return failelist

def build():
    if os.path.exists("D:/Bose.XueLe.WMS"):
        shutil.rmtree("D:/Bose.XueLe.WMS")
    cmdlist = ["cmd.exe","/C","C:/Windows/Microsoft.NET/Framework64/v4.0.30319/msbuild.exe","/t:Build","/p:FrameworkPathOverride=C:/v4.0","/p:Configuration=Release", "/p:WebProjectOutputDir=D:/Bose.XueLe.WMS","/p:OutputPath=D:/Bose.XueLe.WMS/bin", "/p:TargetFrameworkVersion=v4.0", "/p:VisualStudioVersion=12.0", "d:/jenkins/workspace/wms/Bose.XueLe.WMS.sln"]
    ps = subprocess.Popen(cmdlist, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    while True:
        data = ps.stdout.readline()
        if data == b'':
            if ps.poll() is not None:
                break
        else:
            line = data.decode(codecs.lookup(locale.getpreferredencoding()).name)
            print(line)
        
    return ps.returncode

	
	
def setlogging():
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                        datefmt='%a, %d %b %Y %H:%M:%S',
                        filename='c:/myapp.log',
                        filemode='a')

    #################################################################################################
    # 定义一个StreamHandler，将INFO级别或更高的日志信息打印到标准错误，并将其添加到当前的日志处理对象#
    #console = logging.StreamHandler()
    #console.setLevel(logging.INFO)
    #formatter = logging.Formatter('%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)-8s %(message)s')
    #console.setFormatter(formatter)
    #logging.getLogger('').addHandler(console)
    #################################################################################################

if __name__ == "__main__":
    setlogging()
    start = time.time()
    temppath = 'd:/deploy'
    backdir = 'd:/backup'
    filename = os.path.join(temppath, 'Bose.XueLe.WMS.zip')
    destpath = 'D:/Project/Bose.XueLe.WMS'
    downfile = '/var/www/online/wms/Bose.XueLe.WMS.zip'
    if os.path.isfile(filename):
        os.remove(filename)
    temp = os.path.join(temppath, 'Bose.XueLe.WMS')
    if os.path.exists(temp):
        shutil.rmtree(temp)
    name = "Bose.XueLe.WMS-%s.zip" % time.strftime("%Y%m%d%H%M", time.localtime())
    backneme = os.path.join(backdir,name)
    sourcebranch = sys.argv[1]
    fetch_branch(sourcebranch)
    code = build()
    if code == 0:
        zip_dir("D:/Bose.XueLe.WMS","D:/Bose.XueLe.WMS.zip")
        print(destpath)
        if backupFiles(destpath,backneme):
            shutil.copy("d:/Bose.XueLe.WMS.zip",filename)
            if sftpupfile("192.168.1.254", 22, 'deploy', 'xl123456', downfile, filename):
                print("上传文件 %s 成功" % downfile)
                logging.info("上传文件 %s 成功" % downfile)
                if zipExtract(zfilename=filename, temppath=temppath):
                    print("解压文件 %s 成功" % filename)
                    logging.info("解压文件 %s 成功" % filename)
                    srcpath = os.path.join(temppath, 'Bose.XueLe.WMS')
                    if updateFiles(srcpath, destpath):
                        print("更新文件成功...")
                        logging.info("更新文件成功...")
                        result = checkUpdate(zfilename=filename, path=destpath)
                        if result:
                            for f in result:
                                msg = "文件更新失败: %s" % f
                                print(msg)
                                logging.error(msg)
                        else:
                            print("检测更新文件成功...")
                            logging.info("检测更新文件成功...")

    end = time.time() - start

    logging.info("all time %s" % end)

