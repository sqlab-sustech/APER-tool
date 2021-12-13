# APER Tool

#### Downloads

+ Get mapping: <a href="https://github.com/sqlab-sustech/APER-mapping" target="_blank">aper-mapping</a>

+ Get Android jar files (recommended): <a href="https://github.com/CirQ/android-platforms" target="_blank">android-platforms</a>

+ Download FlowDroid's full package: [soot-infoflow-cmd-jar-with-dependencies.jar](https://github.com/secure-software-engineering/FlowDroid/releases/download/v2.7.1/soot-infoflow-cmd-jar-with-dependencies.jar)

#### Install Local Repository and Build

```bash
mvn install:install-file -Dfile=<path-to-flowdroid-jar> \
    -DgroupId=ca.mcgill.sable \
    -DartifactId=soot-infoflow \
    -Dversion=2.7.1 \
    -Dpackaging=jar \
    -DlocalRepositoryPath=lib-repo            # install jar

mvn clean package                             # compile
```

#### Run Aper

```bash
java -jar APER-jar-with-dependencies.jar \    # run Aper
    -s <path-to-android-platforms-directory> \
    -m arp -M <path-to-aper-mapping-directory> \
    --with-exdir --without-obfscan --filter-trycatch \
    <path-to-apk-file>
```

#### Type-1 bug example

**Get APK of app [MemeTastic](https://aper-project.github.io/assets/bin/io.github.gsantner.memetastic_68.apk)**

Run APER will create folder `analyzerOutput/io.github.gsantner.memetastic/`, in the file `empirical/incomplete.txt`:

```bash
<path-to-cwd>/analyzerOutput/io.github.gsantner.memetastic/reports/002-android.os.Environment.getExternalStorageDirectory()java.io.File.txt
```

Which suggests that the calling context in `002` has no checks and contains a Type-1 bug:

```
API:
	<android.os.Environment: java.io.File getExternalStorageDirectory()>
---
PERMISSIONS:
	[android.permission.READ_EXTERNAL_STORAGE,android.permission.WRITE_EXTERNAL_STORAGE]
---
CALLCHAIN:
	net.gsantner.memetastic.activity.MemeCreateActivity.onCreate(android.os.Bundle)void
	 net.gsantner.memetastic.activity.MemeCreateActivity.initMemeSettings(android.os.Bundle)boolean
	  net.gsantner.memetastic.activity.MemeCreateActivity.extractBitmapFromIntent(android.content.Intent)android.graphics.Bitmap
	   net.gsantner.opoc.util.ShareUtil.extractFileFromIntent(android.content.Intent)java.io.File
	    android.os.Environment.getExternalStorageDirectory()java.io.File

======

DANGEROUS: android.permission.READ_EXTERNAL_STORAGE
	Is Declared: true
	Check Sites: NONE
	Request Sites: NONE
	Has Handle: in <net.gsantner.memetastic.activity.MemeCreateActivity: void onRequestPermissionsResult(int,java.lang.String[],int[])>

---
DANGEROUS: android.permission.WRITE_EXTERNAL_STORAGE
	Is Declared: true
	Check Sites: NONE
	Request Sites: NONE
	Has Handle: in <net.gsantner.memetastic.activity.MemeCreateActivity: void onRequestPermissionsResult(int,java.lang.String[],int[])>
```

#### Type-2 bug example

**Get APK of app [OpenTopoMapViewer](https://aper-project.github.io/assets/bin/org.nitri.opentopo_26.apk)**

Run APER will create folder `analyzerOutput/org.nitri.opentopo/`, in the file `compatreport.txt`:

```bash
----------------------------------------
<path-to-cwd>/analyzerOutput/org.nitri.opentopo/reports/005-android.location.LocationManager.addNmeaListener(android.location.OnNmeaMessageListener)boolean.txt
23: RvProtectedAPI
24: OnlyC
25: OnlyC
26: OnlyC
27: OnlyC
28: OnlyC
```

Which means the calling context in `005` invoke dangerous API `addNmeaListener`, its permission is checked in 24-28, but is not checked in 23, thus is a Type-2 bug.
