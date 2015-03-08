#!/usr/bin/env python

##########################################################################
#                                                                        #
#  Utility for autoinstall FTAS patches. Version 0.9b                    #
#                                                                        #
#  Copyright (C) 2010-2011 by Vadim Y. Komarov <dotvad@gmail.com>        #
#                                                                        #
##########################################################################

import optparse
import logging
import os
import sys
import re
from traceback import print_tb, print_exc 
from subprocess import Popen,PIPE,STDOUT 
from string import split, strip, join, replace
import ConfigParser
from time import sleep, strftime
from ftplib import FTP
from stat import S_IRWXU
from shutil import rmtree

# Detect script directory
scrdir = os.path.dirname(__file__)

# Prepare dump file
dumpfile = scrdir + os.sep + "debug.trc"
if os.path.exists(dumpfile):
	os.remove(dumpfile)

# lock-file
lockfile_path = scrdir + os.sep + "lazypatch.lock"
rmlock = True

# Load parameters from config file
config = ConfigParser.ConfigParser()
config.read(scrdir + os.sep + 'lazypatch.conf')
logdir = config.get("lazypatch", "logdir")
installeddir = config.get("lazypatch", "installeddir")
appspwd = config.get("lazypatch", "appspwd")
syspwd = config.get("lazypatch", "syspwd")
sidname = config.get("lazypatch", "sidname")
region = config.get("lazypatch", "region")
osusername = config.get("lazypatch", "osusername")
killblocking = config.get("lazypatch", "killblocking")
reptype = config.get("xdb", "reptype")
xdbhost = config.get("xdb", "xdbhost")
xdbport = config.get("xdb", "xdbport")
xdblogin = config.get("xdb", "xdblogin")
xdbpsw = config.get("xdb", "xdbpwd")
guestpath = config.get("xdb", "guestpath")

if not os.path.exists(logdir):
	os.mkdir(logdir)
if not os.path.exists(installeddir):
	os.mkdir(installeddir)

class Executer:
	def run(self, command, input=None, realtime_logging=True, wd=None):
		if options.debug:
			lazylogger.debug("Executing '%s'" % command)
		try:
			if wd:
				p = Popen(command, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, cwd=wd)
			else:
				p = Popen(command, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
			if input:
				p.stdin.write(input)
			if realtime_logging == True:
				while p.poll() is None:
					out = strip(p.stdout.readline())
					if out: oslogger.info(out)
				return True
			else:
				out = p.stdout.readlines()
				return out
		except OSError, msg:
			lazylogger.error("Cannot execute '%s' command. %s" % (command, msg))
			print_exc(file=open(dumpfile, "a"))
			return False
		except:
			lazylogger.error("Cannot execute '%s' command. %s" % (command, sys.exc_info()[0]))
			print_exc(file=open(dumpfile, "a"))
			return False

class ProcessAction:
	def __init__(self):
		self.ex = Executer()

	def recurse(self, ftp):
		ftp.cwd("/xdo/repository/Reports/Guest")
		for d in ftp.nlst():
			ftp.cwd(d)
			self.cleanOut(ftp)
			ftp.cwd("..")
			ftp.rmd(d)

	def cleanOut(self, ftp):
		for d in ftp.nlst():
			try:
				ftp.delete(d)
			except:
				ftp.cwd(d)
				self.cleanOut(ftp)
				ftp.cwd("..")
				ftp.rmd(d)

	def startapps(self):
		# Platform-specific actions
		if os.name == "nt":
			adstrtal = "adstrtal.cmd"
		elif os.name == "posix":
			adstrtal = "adstrtal.sh"

		lazylogger.info("Starting the appsTier...")

		try:
			if not os.getenv("ADMIN_SCRIPTS_HOME"):
				lazylogger.error("Can't find needed environment variables. Exiting...")
				sys.exit(70)

			if options.runfast:
				lazylogger.info("Removing BI Publisher templates...")
				if reptype == "base":
					try:
						ftp = FTP()
						ftp.connect(xdbhost, xdbport)
						ftp.login(xdblogin, xdbpsw)
						self.recurse(ftp)
						ftp.quit()
					except:
						lazylogger.error("FTP error. %s" % sys.exc_info()[0])
						print_exc(file=open(dumpfile, "a"))
				elif reptype == "files":
					os.rename(guestpath, guestpath + ".faststart")

			if options.checkconc == False:
				lazylogger.info("Updating fnd_concurrent_requests table...")
				self.ex.run("sqlplus -S apps/%s@%s" % (appspwd, sidname),
					"UPDATE fnd_concurrent_requests r SET r.hold_flag='N' WHERE r.request_id IN (SELECT request_id FROM FND_CONC_REQ_SUMMARY_V WHERE requestor = 'XXT_GL_SYSTEM_USER' AND program_short_name IN ('XLAGLTRN','XXT_GL_AUTOPOST','XXT_GL_MEMOSLIP') AND status_code IN ('Q','I')) AND r.hold_flag = 'Y';\ncommit;\nexit;\n")

			# Executing adstrtal
			self.ex.run("%s%s%s apps/%s" % (os.getenv("ADMIN_SCRIPTS_HOME"), os.sep, adstrtal, appspwd))

			if options.runfast:
				lazylogger.info("Registering BI Publister templates...")
				if reptype == "base":
					self.ex.run("sqlplus -S apps/%s@%s" % (appspwd, sidname),
							"exec XXT_RP_BIP_TEST.REG_ALL_REPORT();\nexit;\n")
				elif reptype == "files":
					os.rename(guestpath + ".faststart", guestpath)

		except:
			lazylogger.error("Error being starting appsTier. %s. Exiting..." % sys.exc_info()[0])
			print_exc(file=open(dumpfile, "a"))
			sys.exit(70)

	def stopapps(self):
		# Platform-specific actions
		if os.name == "nt":
			adstpall = "adstpall.cmd"
		elif os.name == "posix":
			adstpall = "adstpall.sh"

		lazylogger.info("Stopping the appsTier...")

		try:
			if not os.getenv("ADMIN_SCRIPTS_HOME"):
				lazylogger.error("Can't find needed environment variables. Exiting...")
				sys.exit(70)

			if options.checkconc == False:
				lazylogger.info("Updating fnd_concurrent_requests table...")
				self.ex.run("sqlplus -S apps/%s@%s" % (appspwd, sidname),
					"UPDATE fnd_concurrent_requests r SET r.hold_flag='Y' WHERE r.request_id IN (SELECT request_id FROM FND_CONC_REQ_SUMMARY_V WHERE requestor='XXT_GL_SYSTEM_USER' AND program_short_name IN ('XLAGLTRN','XXT_GL_AUTOPOST','XXT_GL_MEMOSLIP') AND status_code IN ('Q','I') AND requested_start_date > SYSDATE ) AND r.hold_flag='N';\ncommit;\nexit;\n")
				out = self.ex.run("sqlplus -S apps/%s@%s" % (appspwd, sidname), "SELECT COUNT(*) \"X\" FROM fnd_conc_req_summary_v WHERE requestor = 'XXT_GL_SYSTEM_USER' AND program_short_name IN ('XLAGLTRN', 'XXT_GL_AUTOPOST', 'XXT_GL_MEMOSLIP') AND phase_code= 'R';\nexit;\n", False)
				gl_cnc_count = int(strip(out[3]))
				if gl_cnc_count > 0: # Running
					# Check it
					for i in range(12):
						out = self.ex.run("sqlplus -S apps/%s@%s" % (appspwd, sidname), "SELECT COUNT(*) \"X\" FROM fnd_conc_req_summary_v WHERE requestor = 'XXT_GL_SYSTEM_USER' AND program_short_name IN ('XLAGLTRN', 'XXT_GL_AUTOPOST', 'XXT_GL_MEMOSLIP') AND phase_code= 'R';\nexit;\n", False)
						gl_cnc_count = int(strip(out[3]))
						if gl_cnc_count > 0: # Running
							lazylogger.info("Found %s concurrent for GL posting in running phase. Wait 5 minutes for correct end" % gl_cnc_count)
							sleep(300)
							if i == 11: # Max attemps (1 hour)
								lazylogger.error("Cannot stop appsTier. Found running GL posting.")
								self.ex.run("sqlplus -S apps/%s@%s" % (appspwd, sidname), "UPDATE fnd_concurrent_requests r SET r.hold_flag='N' WHERE r.request_id IN (SELECT request_id FROM FND_CONC_REQ_SUMMARY_V WHERE requestor = 'XXT_GL_SYSTEM_USER' AND program_short_name IN ('XLAGLTRN','XXT_GL_AUTOPOST','XXT_GL_MEMOSLIP') AND status_code IN ('Q','I')) AND r.hold_flag = 'Y';\ncommit;\nexit;\n")
								sys.exit(70)
						elif gl_cnc_count == 0: # Ok
							lazylogger.info("All concurrent for GL posting correct complete.")
							break
				elif gl_cnc_count == 0: # Ok
					lazylogger.info("All concurrent for GL posting correct complete.")

			# Executing adstpall
			self.ex.run("%s%s%s apps/%s" % (os.getenv("ADMIN_SCRIPTS_HOME"), os.sep, adstpall, appspwd))

			if not options.nosleep:
				lazylogger.info("Waiting 15 minutes...")
				sleep(900)

			if not options.nokill:
				# Kill FND processes
				if os.name == "nt":
					lazylogger.info("Killing FND processes...")
					out = self.ex.run("ps -ef | grep -E \"FND|POXCON|RCVOLTM|INCTM|frmweb\" | grep -v grep | awk '{print $2}' | xargs kill -9", realtime_logging=False)
				elif os.name == "posix":
					from signal import SIGTERM
					out = self.ex.run("ps -fu %s | grep -E \"FND|POXCON|RCVOLTM|INCTM|frmweb\" | grep -v grep" %
							osusername, realtime_logging=False)
					if out:
						for line in out:
							pid = split(strip(line))[1]
							lazylogger.info("Killing process by PID %s" % pid)
							try:
								os.kill(int(pid), SIGTERM)
							except:
								pass

		except:
			lazylogger.error("Error being stopping the appsTier. %s. Exiting..." % sys.exc_info()[0])
			print_exc(file=open(dumpfile, "a"))
			sys.exit(70)

	def autoconfigapps(self):
		# Platform-specific actions
		if os.name == "nt":
			adautocfg = "adautocfg.cmd"
		elif os.name == "posix":
			adautocfg = "adautocfg.sh"

		lazylogger.info("Run autoconfig appsTier")

		try:
			if not os.getenv("ADMIN_SCRIPTS_HOME"):
				lazylogger.error("Can't find needed environment variables. Exiting...")
				sys.exit(70)

			# Executing adautocfg
			self.ex.run("%s%s%s" % (os.getenv("ADMIN_SCRIPTS_HOME"), os.sep, adautocfg), "%s\n" % appspwd)

		except:
			lazylogger.error("Error being autoconfig apps. %s. Exiting..." % sys.exc_info()[0])
			print_exc(file=open(dumpfile, "a"))
			sys.exit(70)

	def runcustom(self, filename):
		lazylogger.info("Run commands from %s" % options.customfile)

		try:
			if os.name == "posix":
				os.chmod(filename, S_IRWXU)
			self.ex.run(options.customfile)

		except:
			lazylogger.error("Error being excuting custom scripts. %s. Exiting..." % sys.exc_info()[0])
			print_exc(file=open(dumpfile, "a"))
			sys.exit(70)

class Installer:
	def __init__(self, directory):
		self.directory = directory
		self.ex = Executer()

	def createlist(self):
		if options.debug:
			lazylogger.debug("Creating install list...")
		try:
			if not os.access(self.directory, os.R_OK):
				lazylogger.error("Cannot access to %s. Exiting..." % options.patchdir)
				sys.exit(70)
			filelist = os.listdir(self.directory)

			filelist.sort()

			# Keep only patch files
			patches = re.compile("(\\d+)(\\.)(\\d+)(\\.)((\\d+)|(\\d+)([a-z])|(\\d+)([a-z])(\\d+))(\\.)(zip)", re.IGNORECASE)
			filelist = filter(patches.search, filelist)

			if options.debug:
				lazylogger.debug("Filelist contains: %s" % filelist)

			return filelist

		except:
			lazylogger.error("Cannot create install list. %s" % sys.exc_info()[0])
			print_exc(file=open(dumpfile, "a"))
			return False

	def checklist(self, patchlist):
		if len(patchlist) == 0:
			return
		lazylogger.info("Found %s patches. Check files..." % len(patchlist))
		for patchfile in patchlist:
			patch = Patchfile(patchfile, self.directory)
			if not patch.check():
				lazylogger.error("Patch %s check failed. Exiting..." % patchfile)
				sys.exit(70)
	
	def killblocking(self):
		lazylogger.info("Killing blocking oracle sessions...")
		try:
			self.ex.run("sqlplus -S apps/%s@%s @%s" % (appspwd, sidname, killblocking))

		except:
			lazylogger.error("Cannot kill blocking sessions. %s. Exiting..." % sys.exc_info()[0])
			print_exc(file=open(dumpfile, "a"))
			sys.exit(70)

	def killall(self):
		lazylogger.info("Killing ALL oracle sessions...")
		try:
			if os.name == "nt":
				lazylogger.warning("On your platform SSH functions may not be stable and not working without MKS! If you having trouble please use restart-db flag or contact to me")
			pids = self.ex.run("sqlplus -S apps/%s@%s" % (appspwd, sidname), "set heading off feedback off termout off timing off pagesize 0\nSELECT spid FROM v$session, v$process WHERE v$session.username = 'APPS' AND v$session.paddr = v$process.addr AND v$session.program NOT LIKE 'oracle%';\nexit;\n", False)
			pids = [x.strip() for x in pids]
			dbhost = str(strip(self.ex.run("sqlplus -S apps/%s@%s" % (appspwd, sidname), "set heading off feedback off termout off timing off pagesize 0\nSELECT host || '.' || domain FROM fnd_nodes WHERE support_db = 'Y';\nexit;\n", False)[0]))
			dbusername = str(strip(self.ex.run("sqlplus -S apps/%s@%s" % (appspwd, sidname), "set heading off feedback off termout off timing off pagesize 0\nSELECT DISTINCT osuser FROM v$session WHERE schemaname = 'SYS' AND username IS NULL;\nexit;\n", False)[0]))
			lazylogger.info("Sessions inormation:")
			self.ex.run("sqlplus -S apps/%s@%s" % (appspwd, sidname), "set timing off feedback off pagesize 0 linesize 120\ncolumn spid format a6\ncolumn username format a6\ncolumn status format a8\ncolumn osuser format a10\ncolumn machine format a10\ncolumn program format a20\ncolumn module format a20\nSELECT spid, v$session.username, v$session.status, v$session.osuser, v$session.machine, v$session.program, v$session.module FROM v$session, v$process WHERE v$session.username = 'APPS' AND v$session.paddr = v$process.addr AND v$session.program NOT LIKE 'oracle%';\nexit;\n")
			self.ex.run("sqlplus -S sys/%s@%s as sysdba" % (syspwd, sidname), "BEGIN FOR c_session IN (SELECT s.sid, s.serial# FROM v$session s, v$process p WHERE s.username = 'APPS' AND s.paddr = p.addr AND s.program NOT LIKE 'oracle%') LOOP EXECUTE IMMEDIATE 'alter system kill session ''' || c_session.sid || ',' || c_session.serial# || ''' IMMEDIATE'; END LOOP; END;\n/\nexit;\n", False)
			lazylogger.info("Kill %s processes on %s@%s" % (join(pids), dbusername, dbhost))
			self.ex.run("ssh %s@%s \"kill -9 %s\"" % (dbusername, dbhost, join(pids)), False)

		except:
			lazylogger.error("Cannot kill oracle sessions. %s. Exiting..." % sys.exc_info()[0])
			print_exc(file=open(dumpfile, "a"))
			sys.exit(70)

	def installall(self, patchlist):
		lazylogger.info("Found %s patches. Start installation..." % len(patchlist))

		if not os.getenv("APPLTMP"):
			lazylogger.error("Can't find needed environment variables. Exiting...")
			sys.exit(70)

		try:
			if options.killall == True:
				self.killall()
			if not options.norestartdb:
				# Restart database
				lazylogger.info("Try to restart database, please wait...")
				# Get a db environment file path on db host
				db_ohome = str(strip(self.ex.run("sqlplus -S apps/%s@%s" % (appspwd, sidname), "set heading off feedback off termout on timing off pagesize 0\nVAR OHM VARCHAR2(255);\nEXEC DBMS_SYSTEM.GET_ENV('ORACLE_HOME', :OHM);\nPRINT OHM;\nexit;\n", False)[0]))
				db_short_host = str(strip(self.ex.run("sqlplus -S apps/%s@%s" % (appspwd, sidname), "set heading off feedback off termout off timing off pagesize 0\nSELECT host FROM fnd_nodes WHERE support_db = 'Y';\nexit;\n", False)[0]))
				db_envfile = db_ohome + os.sep + sidname + "_" + db_short_host + ".env"
				db_envfile = db_envfile.replace('\\', '/')
				lazylogger.info("db environment file=%s" % db_envfile)
				dbhost = str(strip(self.ex.run("sqlplus -S apps/%s@%s" % (appspwd, sidname), "set heading off feedback off termout off timing off pagesize 0\nSELECT host || '.' || domain FROM fnd_nodes WHERE support_db = 'Y';\nexit;\n", False)[0]))
				dbusername = str(strip(self.ex.run("sqlplus -S apps/%s@%s" % (appspwd, sidname), "set heading off feedback off termout off timing off pagesize 0\nSELECT DISTINCT osuser FROM v$session WHERE schemaname = 'SYS' AND username IS NULL;\nexit;\n", False)[0]))
				# Stop listener
				self.ex.run("ssh %s@%s \". %s; lsnrctl stop %s\"" % (dbusername, dbhost, db_envfile, sidname), False)
				self.ex.run("ssh %s@%s \". %s; sqlplus -S / as sysdba\"" % (dbusername, dbhost, db_envfile), "alter system flush shared_pool;\nalter system flush buffer_cache;\nalter system checkpoint;\nexit;\n", False)
				out = self.ex.run("ssh %s@%s \". %s; sqlplus -S / as sysdba\"" % (dbusername, dbhost, db_envfile), "shutdown immediate;\nstartup;\n\nexit;\n", False)
				lazylogger.info("Restart say:\n%s" % join(out))
				if strip(out[3]) != 'ORACLE instance started.':
					lazylogger.info("Cannot restart database. Exiting...")
					sys.exit(70)
				# Start listener
				self.ex.run("ssh %s@%s \". %s; lsnrctl start %s\"" % (dbusername, dbhost, db_envfile, sidname), False)
				lazylogger.info("Restart database done.")

			for patchfile in patchlist:
				patch = Patchfile(patchfile, self.directory)
				if patch.check():
					patch.extract(os.getenv("APPLTMP"))
					if options.killblock == True:
						self.killblocking()
					if options.norunpost == False:
						patch.install()
					elif options.norunpost == True:
						if patchfile != patchlist[-1]:
							if patchfile.lower().endswith('c.zip'):
								#postload after cumulative
								patch.install(runpost=True)
							else:
								patch.install(runpost=False)
						elif patchfile == patchlist[-1]:
							patch.install(runpost=True)
					patch.logprepare()
					mvtarget = installeddir + os.sep + patchfile
					if not os.access(mvtarget, os.R_OK):
						os.rename(self.directory + os.sep + patchfile, mvtarget)
					else:
						os.remove(mvtarget)
						os.rename(self.directory + os.sep + patchfile, mvtarget)
				else:
					lazylogger.error("Patch %s check failed. Exiting..." % patchfile)
					sys.exit(70)

		except:
			lazylogger.error("Cannot install patches. %s. Exiting..." % sys.exc_info()[0])
			print_exc(file=open(dumpfile, "a"))
			sys.exit(70)

class Patchfile:
	def __init__(self, filename, directory):
		self.filename = filename
		self.directory = directory
		self.wd = os.getenv("APPLTMP") + os.sep + self.filename[:-4]
		self.ex = Executer()

	def check(self):
		lazylogger.info("Checking %s..." % self.filename)

		try:
			out = self.ex.run("unzip -t %s" % self.filename, realtime_logging=False, wd=self.directory)
			if strip(out[-1:][0]) == "No errors detected in compressed data of %s." % self.filename:
				lazylogger.info(strip(out[-1:][0]))
				return True
			else:
				lazylogger.error(strip(out[-1:][0]))
				return False

		except:
			lazylogger.error("Patch check failed. %s. Exiting..." % sys.exc_info()[0])
			print_exc(file=open(dumpfile, "a"))
			sys.exit(70)

	def extract(self, destination):
		lazylogger.info("Start extracting %s to %s..." % (self.filename, os.getenv("APPLTMP")))

		try:
			if os.access(self.wd, os.R_OK):
				lazylogger.info("Removing %s" % self.wd)
				rmtree(self.wd)
			self.ex.run("unzip %s -d %s" % (self.filename, os.getenv("APPLTMP")), wd=self.directory)

		except:
			lazylogger.error("Cannot extract patch. %s. Exiting..." % sys.exc_info()[0])
			print_exc(file=open(dumpfile, "a"))
			sys.exit(70)

	def install(self, runpost = True):
		if os.name == "nt":
			xxt_patch = "xxt_patch_t.cmd"
		elif os.name == "posix":
			xxt_patch = "xxt_patch.sh"

		if not os.getenv("APPLTMP"):
			lazylogger.error("Can't find needed environment variables. Exiting...")
			sys.exit(70)

		if not os.access(self.wd, os.W_OK):
			lazylogger.error("Cannot access to %s. Exiting..." % self.wd)
			sys.exit(70)

		lazylogger.info("Start installation from %s" % self.wd)

		try:
			# Install patch
			if runpost == True:
				self.ex.run("%s%sadmin%s%s patch=." %
						(os.getenv("XXT_TOP"), os.sep, os.sep, xxt_patch),
						"apps\n%s\n" % appspwd, wd=self.wd)
			elif runpost == False:
				self.ex.run("%s%sadmin%s%s patch=. run_post=N" %
						(os.getenv("XXT_TOP"), os.sep, os.sep, xxt_patch),
						"apps\n%s\n" % appspwd, wd=self.wd)
		except:
			lazylogger.error("Cannot install patch. %s. Exiting..." % sys.exc_info()[0])
			print_exc(file=open(dumpfile, "a"))
			sys.exit(70)

	def logprepare(self):
		lazylogger.info("Preparing logs for send...")
		try:
			loglist = os.listdir(self.wd)
			logs = re.compile("((\\d+)(\\.)(log|out|err))|(region.err)", re.IGNORECASE)
			loglist = filter(logs.search, loglist)
			self.ex.run("zip %s%s%s.%s.%s %s" %
					(logdir, os.sep, region, sidname, self.filename, join(loglist)),
					wd=self.wd)

		except:
			lazylogger.error("Cannot prepare logs for send. %s. Exiting..." % sys.exc_info()[0])
			print_exc(file=open(dumpfile, "a"))
			sys.exit(70)

if __name__=="__main__":
	parser = optparse.OptionParser(usage="usage: %prog [options]",
			version="version: %prog 0.9b")
	parser.add_option("-d", "--debug", action="store_true", dest="debug",
			default=False, help="print debug messages")
	parser.add_option("-p", "--patch-dir", dest="patchdir", help="directory to patches",
			metavar="PATCHDIR")
	parser.add_option("-k", "--kill-blocking", action="store_true", dest="killblock",
			default=False, help="kill blocking oracle sessions before patching")
	parser.add_option("-K", "--kill-all", action="store_true", dest="killall",
			default=False, help="kill ALL oracle sessions before patching")
	parser.add_option("-n", "--nosleep", action="store_true", dest="nosleep",
			default=False, help="don't wait before killing FNDs")
	parser.add_option("-i", "--nokill", action="store_true", dest="nokill",
			default=False, help="don't kill any processes")
	parser.add_option("-s", "--nostop", action="store_true", dest="nostop",
			default=False, help="don't stopping the appsTier")
	parser.add_option("-b", "--no-restart-db", action="store_true", dest="norestartdb",
			default=False, help="don't restart database before install patches")
	parser.add_option("-r", "--norunpost", action="store_true", dest="norunpost",
			default=False, help="run_post=N for all patches except last")
	parser.add_option("-f", "--run-fast", action="store_true", dest="runfast",
			default=False, help="clear BI templates before run oacore and register after")
	parser.add_option("-q", "--no-check-conc", action="store_true", dest="checkconc",
			default=False, help="disable check system concurrents")
	parser.add_option("-a", "--run-autoconfig", action="store_true", dest="runautoconfig",
			default=False, help="run autoconfig before starting appsTier")
	parser.add_option("-c", "--custom-file", dest="customfile", help="custom command file",
			metavar="CUSTOMFILE")
	(options, args) = parser.parse_args()

	try:
		# Set logging parameters
		logfilename = logdir + os.sep + sidname + "_" + strftime("%Y-%m-%d_%H-%M-%S") + ".log"
		lazylogger = logging.getLogger("lazypatch")
		lazylogger.setLevel(logging.DEBUG)
		oslogger = logging.getLogger("osout")
		oslogger.setLevel(logging.DEBUG)

		formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

		consoleHandler = logging.StreamHandler()
		consoleHandler.setLevel(logging.DEBUG)
		consoleHandler.setFormatter(formatter)

		fileHandler = logging.FileHandler(logfilename)
		fileHandler.setLevel(logging.DEBUG)
		fileHandler.setFormatter(formatter)

		lazylogger.addHandler(consoleHandler)
		lazylogger.addHandler(fileHandler)
		oslogger.addHandler(consoleHandler)
		oslogger.addHandler(fileHandler)

		# Detect another runnuing lazypatch
		if os.path.exists(lockfile_path):
			lazylogger.error("Another lazypatch is running. Exiting...")
			rmlock = False
			sys.exit(70)

		# Create lock-file
		lockfile = open(lockfile_path, "w")
		lockfile.write(str(os.getpid()))
		lockfile.close()

		pactor = ProcessAction()

		if not options.patchdir and not options.runautoconfig and not options.customfile:
			lazylogger.info("Nothing to do. Exiting...")
			sys.exit(0)

		elif not options.patchdir and options.runautoconfig and not options.customfile:
			pactor.stopapps()
			pactor.autoconfigapps()
			pactor.startapps()

		elif not options.patchdir and not options.runautoconfig and options.customfile:
			pactor.stopapps()
			pactor.runcustom(options.customfile)
			pactor.startapps()

		elif not options.patchdir and options.runautoconfig and options.customfile:
			pactor.stopapps()
			pactor.autoconfigapps()
			pactor.runcustom(options.customfile)
			pactor.startapps()

		elif options.patchdir:
			installer = Installer(options.patchdir)
			patchlist = installer.createlist()
			installer.checklist(patchlist)

			if not patchlist and not options.runautoconfig and not options.customfile:
				lazylogger.info("Nothing to do. Exiting...")
				sys.exit(0)

			if not patchlist and options.runautoconfig and not options.customfile:
				pactor.stopapps()
				pactor.autoconfigapps()
				pactor.startapps()

			if not patchlist and not options.runautoconfig and options.customfile:
				pactor.stopapps()
				pactor.runcustom(options.customfile)
				pactor.startapps()

			if not patchlist and options.runautoconfig and options.customfile:
				pactor.stopapps()
				pactor.autoconfigapps()
				pactor.runcustom(options.customfile)
				pactor.startapps()

			elif patchlist and not options.runautoconfig and not options.customfile:
				if options.nostop:
					lazylogger.info("Don't stopping appsTier.")
					installer.installall(patchlist)
				else:
					pactor.stopapps()
					installer.installall(patchlist)
					pactor.startapps()

			elif patchlist and options.runautoconfig and not options.customfile:
				pactor.stopapps()
				installer.installall(patchlist)
				pactor.autoconfigapps()
				pactor.startapps()

			elif patchlist and not options.runautoconfig and options.customfile:
				pactor.stopapps()
				installer.installall(patchlist)
				pactor.runcustom(options.customfile)
				pactor.startapps()

			elif patchlist and options.runautoconfig and options.customfile:
				pactor.stopapps()
				installer.installall(patchlist)
				pactor.autoconfigapps()
				pactor.runcustom(options.customfile)
				pactor.startapps()

	except SystemExit:
		if rmlock == True:
			os.remove(lockfile_path)

	except:
		lazylogger.error("Main: %s. Exiting..." % sys.exc_info()[0])
		print_exc(file=open(dumpfile, "a"))
		if rmlock == True:
			os.remove(lockfile_path)
		sys.exit(70)

	if rmlock == True:
		os.remove(lockfile_path)
