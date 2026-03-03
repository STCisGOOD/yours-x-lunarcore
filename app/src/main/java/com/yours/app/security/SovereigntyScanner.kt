package com.yours.app.security

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings
import android.util.Log
import android.view.accessibility.AccessibilityManager
import java.io.File
import java.security.KeyStore
import java.security.cert.X509Certificate

/**
 * On-device sovereignty scanner for detecting compromise indicators.
 *
 * Counter-Intelligence Framework (informed by Snowden archive analysis):
 *
 * 1. NSA attacks ENDPOINTS, not crypto - detect implant behavioral patterns
 * 2. TURBINE/FOXACID deploy automated malware - detect known signatures
 * 3. Implants need permissions (mic/camera/location) - audit for red flags
 * 4. Accessibility services = keylogger vector - flag all enabled services
 * 5. User CA certs enable MITM - critical security check
 *
 * This scanner doesn't detect "GROK" specifically - it detects the
 * BEHAVIORAL PATTERNS any endpoint implant must exhibit.
 */
object SovereigntyScanner {

    // =========================================================================
    // THREAT DATABASE (from sovereignty-scanner bloatware.rs)
    // Only critical/high threats included for on-device efficiency
    // =========================================================================

    // =========================================================================
    // COMPREHENSIVE SURVEILLANCE PACKAGE DATABASE - 400+ PACKAGES
    // Sources: Universal Android Debloater, Exodus Privacy (196+ trackers),
    // Trinity College Dublin research, GrapheneOS, CalyxOS, XDA Forums,
    // stalkerware-indicators, EFF research, FCC carrier investigations
    //
    // Categories: Biometrics, Location, Listening, AI, Silent Installers,
    // Analytics, Carrier (Verizon/AT&T/T-Mobile/Sprint), Corporate, Updates,
    // Knox, Samsung, Google, Facebook/Meta, Chinese Tech (Tencent/Baidu/Alibaba),
    // Attribution SDKs, Session Recording, Device Fingerprinting, Location Brokers
    // =========================================================================

    private val CRITICAL_PACKAGES = setOf(
        // =========================================================================
        // Source: Trinity College Dublin research, Exodus Privacy, UAD-NG
        // =========================================================================

        // === BIOMETRICS - Captures irreversible identity data ===
        "com.samsung.android.smartface",
        "com.samsung.faceservice",
        "com.samsung.android.server.iris",
        "com.sec.factory.iris.usercamera",
        "com.samsung.android.biometrics.app.setting",
        "com.samsung.android.bio.face.service",

        // === ALWAYS LISTENING - 24/7 microphone access ===
        "com.samsung.android.bixby.wakeup",
        "com.android.hotwordenrollment.okgoogle",
        "com.android.hotwordenrollment.xgoogle",
        "com.samsung.android.svoice",
        "com.samsung.android.voicewakeup",
        "com.samsung.android.svoiceime",

        // === LOCATION TRACKING - Constant position monitoring ===
        "com.samsung.android.ipsgeofence",
        "com.google.android.gms.location.history",
        "com.sec.location.nsflp2",
        "com.samsung.android.location",
        "com.samsung.android.mapsagent",
        "com.samsung.android.samsungpositioning",
        "com.verizon.llkagent",              // Verizon Location Agent - continuous GPS

        // === AI SURVEILLANCE - Behavioral profiling ===
        "com.google.android.aicore",
        "com.google.android.as",
        "com.google.android.as.oss",
        "com.samsung.android.rubin.app",     // Customization Service - collects contacts, SMS, location, browsing
        "com.samsung.android.visionintelligence",
        "com.samsung.android.smartsuggestions",
        "com.samsung.android.aware.service",

        // === SILENT INSTALLERS - Backdoors ===
        "com.LogiaGroup.LogiaDeck",          // DT Ignite (Verizon)
        "com.dti.att",                       // DT Ignite (AT&T)
        "com.dti.samsung",                   // DT Ignite (Samsung)
        "com.dti.folderlauncher",
        "com.dti.tracfone",
        "com.digitalturbine.ignite",         // DT Ignite (generic)
        "com.facebook.appmanager",           // Facebook backdoor
        "com.facebook.system",               // Hidden FB services - connects to FB without app
        "com.facebook.services",
        "com.aura.oobe.samsung",             // ironSource AppCloud
        "com.aura.oobe.samsung.gl",          // AppCloud global
        "com.aura.oobe.att",
        "com.ironsource.appcloud.oobe",      // Collects age, gender, IMEI
        "com.sec.android.preloadinstaller",
        "com.vodafone.appbox",               // EU carrier installer

        // === CARRIER ROOTKITS ===
        "com.att.iqi",                       // Carrier IQ - logged keystrokes, SMS, location
        "com.carrieriq.iqagent",             // Carrier IQ agent

        // === VISION/CAMERA AI ===
        "com.samsung.android.visioncloudagent",  // Uploads visual data to cloud

        // === GOOGLE CORE SURVEILLANCE ===
        "com.google.android.gms",            // Play Services - device ID, location, app usage to Google
        "com.google.android.gsf",            // Google Services Framework - GSF ID tracking

        // === DATA HARVESTING - Cloud sync without E2E encryption ===
        "com.samsung.android.scloud",        // Samsung Cloud - some data NOT encrypted

        // === CRITICAL SAMSUNG TELEMETRY ===
        "com.samsung.android.voc",           // Samsung Members - crash data, device identifiers
        "com.samsung.android.mobileservice", // Samsung account telemetry linked to IMEI
        "com.samsung.klms",                  // Knox license management
        "com.samsung.android.securitylogagent", // Security telemetry - 100+ signals

        // === DEVICE FINGERPRINTING ===
        "com.threatmetrix",                  // Behavioral biometrics, device fingerprinting
        "com.iovation",                      // Device reputation, fraud signals
        "com.biocatch",                      // Behavioral biometrics

        // === SESSION RECORDING - Records everything on screen ===
        "com.fullstory",                     // Session recordings
        "com.smartlook.android",             // Screen recordings, heatmaps
        "com.uxcam",                         // Session replay, touch heatmaps
        "com.logrocket",                     // Session replay

        // === CHINESE TECH SDKs - High surveillance risk ===
        "cn.jpush",                          // JiGuang - collects IMEI, MAC, GPS, installed apps
        "cn.jiguang",                        // JiGuang framework
        "com.baidu.lbs",                     // Baidu Location
        "com.baidu.map.location",            // Baidu Location SDK

        // === LOCATION DATA BROKERS ===
        "com.safegraph",                     // SafeGraph SDK (banned by Google)
        "com.xmode",                         // X-Mode/Outlogic SDK
        "com.veraset",                       // Veraset SDK
        "com.cuebiq",                        // Cuebiq SDK
        "com.gravy.analytics",               // Gravy Analytics

        // === FAMILY/STALKER TRACKING ===
        "com.att.securefamily",              // AT&T family location tracking
        "com.att.familymap",                 // AT&T FamilyMap - real-time location history
        "com.google.android.gms.supervision", // Family Link - tracks children

        // === QUALCOMM SURVEILLANCE (from S23 audit) ===
        "com.qualcomm.location",             // Sends device ID, IP, app list to Qualcomm even with GPS off

        // === GOOGLE ON-DEVICE SURVEILLANCE (from S23 audit) ===
        "com.google.android.ondevicepersonalization.services", // Forensic goldmine - timelines ALL activity including deleted apps

        // === SAMSUNG KNOX GUARD (from S23 audit) ===
        "com.samsung.android.kgclient",      // Knox Guard - can remotely lock/brick device, persistent tracking
    )

    private val HIGH_RISK_PACKAGES = setOf(
        // =========================================================================
        // HIGH RISK: Significant data collection, tracking, profiling
        // Source: Trinity College Dublin, Exodus Privacy, UAD-NG, carrier analysis
        // =========================================================================

        // === SAMSUNG ANALYTICS & TELEMETRY ===
        "com.samsung.android.knox.analytics.uploader",
        "com.samsung.android.dqagent",
        "com.samsung.carrier.logcollector",
        "com.samsung.android.networkdiagnostic",
        "com.sec.android.diagmonagent",
        "com.samsung.fresco.logging",
        "com.samsung.storyservice",
        "com.samsung.android.wellbeing",
        "com.samsung.android.lool",          // Device Care - uses Qihoo 360 (China)
        "com.samsung.android.app.usagestatistics",
        "com.samsung.android.forest",        // Digital Wellbeing

        // === GOOGLE TELEMETRY ===
        "com.google.mainline.telemetry",
        "com.google.android.feedback",
        "com.google.android.apps.wellbeing",
        "com.google.android.apps.turbo",     // Device Health - reports every 5 seconds

        // === KEYBOARDS - Typing data collection ===
        "com.touchtype.swiftkey",
        "com.google.android.inputmethod.latin", // Gboard - sends metadata to Google
        "com.samsung.android.honeyboard",    // Samsung Keyboard - clipboard interception
        "com.sohu.inputmethod.sogou.xiaomi", // Sogou Keyboard (Chinese)
        "com.iflytek.inputmethod.miui",      // iFlytek (Chinese)
        "com.baidu.input",                   // Baidu Input (Chinese)

        // === VERIZON CARRIER ===
        "com.vzw.hss.myverizon",
        "com.verizon.messaging.vzmsgs",
        "com.verizon.mips.services",
        "com.verizon.obdm",
        "com.verizon.obdm_permissions",
        "com.verizon.services",
        "com.vcast.mediamanager",
        "com.vzw.ecid",                      // Call Filter - full call history
        "com.asurion.android.verizon.vms",
        "com.verizon.remoteSimlock",
        "com.vznavigator.Generic",
        "com.vzw.apnservice",
        "com.synchronoss.dcs.verizon",       // Verizon Cloud
        "com.telecomsys.directedsms.android.SCG", // Location SMS

        // === AT&T CARRIER ===
        "com.att.myWireless",
        "com.att.android.attsmartwifi",
        "com.att.callprotect",
        "com.att.dh",                        // Device Help - mic, location, storage access
        "com.att.mobilesecurity",            // ActiveArmor
        "com.att.thanks",
        "com.wavemarket.waplauncher",
        "com.synchronoss.dcs.att.r2g",
        "com.asurion.android.protech.att",

        // === T-MOBILE/SPRINT CARRIER ===
        "com.tmobile.pr.mytmobile",
        "com.tmobile.pr.adapt",
        "com.tmobile.services.nameid",
        "com.tmobile.echolocate",            // T-Mobile diagnostics - cannot disable
        "com.tmobile.rsuadapter.qualcomm",
        "com.sprint.care",
        "com.sprint.ms.smf.services",
        "com.sprint.ms.cdm",
        "com.sprint.ce.updater",
        "com.sprint.w.installer",
        "com.sprint.zone",
        "com.locationlabs.finder.sprint",
        "com.android.sdm.plugins.sprintdm",

        // === FACEBOOK/META ECOSYSTEM ===
        "com.facebook.katana",
        "com.facebook.orca",
        "com.facebook.lite",
        "com.instagram.android",
        "com.whatsapp",                      // Meta-owned

        // === GOOGLE APPS WITH TRACKING ===
        "com.google.android.gms.ads",
        "com.google.android.apps.photos",    // $100M BIPA settlement - facial recognition
        "com.google.android.apps.maps",      // Location Timeline
        "com.google.android.googlequicksearchbox", // Assistant - voice recordings
        "com.google.android.apps.googleassistant",
        "com.android.chrome",                // Extensive tracking even with privacy settings
        "com.google.android.apps.fitness",   // Google Fit
        "com.google.android.health.connect.backuprestore",
        "com.google.android.healthconnect.controller",
        "com.google.android.adservices.api", // Privacy Sandbox
        "com.google.mainline.adservices",
        "com.google.android.gm",             // Gmail - AI scans emails
        "com.google.android.apps.docs",      // Google Drive - not zero-knowledge
        "com.google.android.dialer",         // Sends data to Firebase without consent
        "com.google.android.apps.messaging", // RCS metadata collection
        "com.google.android.apps.adm",       // Find My Device - crowdsourced location
        "com.google.android.backup",
        "com.google.android.syncadapters.contacts",
        "com.google.android.webview",        // Safe Browsing tracks URLs
        "com.google.android.lenss",          // Lens - images uploaded to cloud
        "com.google.android.youtube",
        "com.google.android.projection.gearhead", // Android Auto - collects vehicle data

        // === SAMSUNG CLOUD & TRACKING ===
        "com.samsung.android.fmm",           // Find My Mobile
        "com.samsung.android.fmm.nui.receiver",
        "com.samsung.android.app.find",
        "com.sec.android.app.shealth",       // Samsung Health

        // === KNOX ENTERPRISE ===
        "com.sec.enterprise.knox.cloudmdm.smdms",
        "com.samsung.klmsagent",
        "com.samsung.android.knox.containercore",
        "com.samsung.android.knox.kpu",
        "com.samsung.android.knox.attestation",
        "com.samsung.android.knox.pushmanager",
        "com.samsung.android.knox.analytics",
        "com.samsung.android.mdm",
        "com.samsung.syncmlclient",

        // === BEACON/BT TRACKING ===
        "com.samsung.android.beaconmanager",

        // === CORPORATE BLOAT ===
        "com.microsoft.skydrive",
        "com.linkedin.android",              // Sends telemetry without opening
        "com.hiya.star",
        "com.microsoft.appmanager",          // Link to Windows telemetry

        // === AI ASSISTANTS ===
        "com.google.android.apps.bard",
        "com.samsung.android.bixby.agent",
        "com.samsung.android.bixby.service",
        "com.samsung.android.bixbyvision.framework",

        // === UPDATE SERVICES (can reinstall bloatware) ===
        "com.sec.android.soagent",
        "com.samsung.android.app.updatecenter",
        "com.samsung.android.gru",
        "com.google.android.configupdater",
        "com.samsung.android.sdm.config",
        "com.samsung.knox.appsupdateagent",
        "com.google.android.partnersetup",
        "com.samsung.android.app.omcagent",
        "com.samsung.android.svcagent",
        "com.samsung.android.bbc.bbcagent",

        // === AR/FACE DATA ===
        "com.samsung.android.aremoji",       // 100+ facial feature points
        "com.samsung.android.arzone",
        "com.samsung.android.aremojieditor",
        "com.google.ar.core",

        // === THIRD-PARTY ADVERTISING SDKs ===
        "com.google.android.gms.ads",
        "com.facebook.ads",
        "com.unity3d.ads",
        "com.ironsource",
        "com.applovin",
        "com.chartboost",
        "com.vungle",
        "com.adcolony",
        "com.inmobi",
        "com.startapp.sdk",
        "com.mintegral",
        "com.bytedance.sdk",                 // Pangle (TikTok Ads)
        "com.tapjoy",
        "com.fyber",

        // === ATTRIBUTION SDKs ===
        "com.appsflyer",
        "com.adjust.sdk",
        "io.branch.referral",
        "com.kochava.base",
        "com.singular.sdk",
        "com.tenjin",

        // === ANALYTICS SDKs ===
        "com.google.firebase",
        "com.flurry.android",
        "com.amplitude.api",
        "com.mixpanel.android",
        "com.segment.analytics",
        "com.mparticle",
        "com.localytics",
        "com.clevertap",
        "com.braze",
        "com.leanplum",
        "com.moengage",
        "com.heap.android",
        "com.comscore",

        // === CHINESE TECH SDKs ===
        "com.tencent.stat",
        "com.baidu.mobstat",
        "com.alibaba",
        "com.umeng",
        "com.huawei.hms.hianalytics",
        "com.xiaomi.xmsf",

        // === IMS/LOGGING ===
        "com.sec.imslogger",                 // VoLTE/RCS message logging

        // === CALLER ID SERVICES ===
        "com.cequint.ecid",                  // T-Mobile Name ID

        // === XIAOMI TELEMETRY ===
        "com.miui.analytics",                // Sends 100x daily to Chinese servers
        "com.miui.daemon",
        "com.miui.systemAdSolution",
        "com.miui.msa.global",

        // === ONEPLUS TELEMETRY ===
        "com.oneplus.odm",                   // Sends IMEI, MAC
        "com.oneplus.opbugreportlite",

        // === SOCIAL MEDIA SDKs ===
        "com.ss.android.ugc.aweme",          // TikTok
        "com.zhiliaoapp.musically",          // TikTok international

        // === S23 AUDIT - HIGH RISK MISSING ===
        "com.samsung.android.visual.cloudcore", // Uploads photos to Samsung cloud for AI
        "com.samsung.android.intellivoiceservice", // Voice data collection, retained by Samsung
        "com.samsung.android.smartcallprovider", // Third-party (Hiya) data sharing confirmed
        "com.samsung.android.wifi.ai",       // Location tracking via cell-based geofencing
        "com.google.android.federatedcompute", // AI training on your data, model inversion attacks
        "com.google.android.apps.restore",   // Full backup data, some NOT encrypted
        "com.samsung.obdmpermission",        // Carrier remote device management
        "com.qualcomm.qti.services.systemhelper", // Extensive system permissions
        "com.samsung.vzwapiservice",         // Verizon API service
    )

    // Medium risk packages - tracked but lower penalty
    private val MEDIUM_RISK_PACKAGES = setOf(
        // =========================================================================
        // MEDIUM RISK: Potential tracking, unnecessary data collection
        // Source: UAD-NG, Exodus Privacy, XDA Forums
        // =========================================================================

        // === BIXBY ===
        "com.samsung.android.app.spage",
        "com.samsung.android.app.routines",
        "com.samsung.android.bixby.voiceinput",
        "com.samsung.android.bixby.plmsync",
        "com.systemui.bixby",
        "com.systemui.bixby2",
        "com.samsung.android.bixby.agent.dummy",

        // === SAMSUNG PAY ===
        "com.samsung.android.spay",
        "com.samsung.android.spayfw",
        "com.samsung.android.samsungpass",
        "com.samsung.android.samsungpassautofill",
        "com.samsung.android.authfw",

        // === SAMSUNG APPS ===
        "com.sec.android.app.samsungapps",   // Galaxy Store
        "com.samsung.android.themestore",
        "com.samsung.android.themecenter",
        "com.sec.android.app.sbrowser",
        "com.samsung.android.oneconnect",    // SmartThings - IoT data
        "com.samsung.android.app.parentalcare",
        "com.samsung.android.app.tips",
        "com.samsung.android.app.social",    // What's New - marketing
        "com.samsung.android.smartswitchassistant",
        "com.samsung.android.app.watchmanager",
        "com.samsung.android.app.watchmanagerstub",
        "com.samsung.android.calendar",
        "com.samsung.android.messaging",
        "com.samsung.android.email.provider",
        "com.samsung.android.app.notes",
        "com.samsung.android.app.reminder",
        "com.samsung.android.app.sharelive",
        "com.samsung.android.app.dressroom",
        "com.sec.android.app.sbrowser",
        "com.samsung.android.app.galaxyfinder",
        "com.samsung.android.applock",
        "com.samsung.android.coldwalletservice",
        "com.samsung.android.dkey",
        "com.samsung.android.carkey",

        // === GOOGLE APPS ===
        "com.google.android.apps.tachyon",   // Google Duo
        "com.google.audio.hearing.visualization.accessibility.scribe",
        "com.google.android.calendar",
        "com.google.android.apps.nbu.paisa.user", // Google Pay
        "com.google.android.apps.magazines",
        "com.google.android.apps.podcasts",
        "com.google.android.apps.youtube.music",
        "com.google.android.videos",
        "com.google.android.apps.subscriptions.red", // Google One
        "com.google.android.syncadapters.calendar",
        "com.google.android.tts",
        "com.google.android.gms.nearby",
        "com.android.vending",               // Play Store - tracks installed apps
        "com.google.android.ext.services",
        "com.google.android.onetimeinitializer",

        // === SAMSUNG GAMING ===
        "com.samsung.android.game.gos",      // Game Optimizing Service
        "com.samsung.android.game.gamehome", // Game Launcher
        "com.samsung.android.game.gametools",
        "com.samsung.android.game.gameboard",

        // === SAMSUNG DEX/LINK ===
        "com.samsung.android.mdx",           // Link to Windows
        "com.samsung.android.mdx.kit",

        // === VISUAL VOICEMAIL ===
        "com.samsung.vvm",
        "com.att.mobile.android.vvm",
        "com.tmobile.vvm.application",
        "com.att.vvm",
        "com.verizon.voicemail",
        "com.comcast.modesto.vvm.client",
        "com.samsung.vmmhux",

        // === SAMSUNG AR ===
        "com.samsung.android.ardrawing",
        "com.samsung.android.livestickers",
        "com.samsung.android.stickercenter",

        // === SAMSUNG MISC ===
        "com.samsung.android.da.daagent",
        "de.axelspringer.yana.zeropage",     // Upday
        "com.samsung.android.sm.devicesecurity",
        "com.samsung.android.sm.policy",
        "com.samsung.android.dialer.tracker",
        "com.samsung.android.allshare.service.fileshare",
        "com.samsung.android.allshare.service.mediashare",
        "com.sec.spp.push",                  // Samsung Push Service
        "com.samsung.android.kidsinstaller",
        "com.samsung.android.shortcutbackupservice",
        "com.sec.android.daemonapp",         // Weather - location
        "com.samsung.android.mateagent",     // Galaxy Friends
        "com.samsung.android.drivelink.stub",
        "com.samsung.android.app.ledbackcover",
        "com.samsung.android.app.cocktailbarservice", // Edge panels
        "com.samsung.android.app.appsedge",
        "com.sec.android.easyonehand",

        // === CARRIER MDM/CONFIG ===
        "com.wsomacp",                       // OMA client provisioning
        "com.android.providers.partnerbookmarks",
        "com.lookout",                       // Lookout Mobile Security

        // === CRASH REPORTING SDKs ===
        "com.google.firebase.crashlytics",
        "com.bugsnag.android",
        "io.sentry",
        "com.instabug.library",
        "ch.acra",
        "com.newrelic.agent.android",
        "io.embrace",

        // === PUSH NOTIFICATION SDKs ===
        "com.onesignal",
        "com.urbanairship",
        "com.getui",                         // Chinese push
        "com.xiaomi.mipush",

        // === A/B TESTING SDKs ===
        "com.optimizely",
        "com.launchdarkly",
        "com.apptimize",

        // === HUAWEI HMS ===
        "com.huawei.hms",
        "com.huawei.hwid",
        "com.huawei.lbs",
        "com.huawei.appmarket",
        "com.huawei.wallet",
        "com.huawei.browser",
        "com.huawei.systemmanager",
        "com.huawei.hicloud",
        "com.huawei.cloud",
        "com.huawei.vassistant",

        // === XIAOMI APPS ===
        "com.xiaomi.market",
        "com.xiaomi.mipicks",
        "com.xiaomi.payment",
        "com.miui.cloudservice",
        "com.miui.cloudbackup",
        "com.miui.player",
        "com.miui.video",
        "com.miui.gallery",
        "com.miui.cleanmaster",
        "com.xiaomi.glgm",

        // === CHINESE APPS ===
        "com.tencent.mm",                    // WeChat
        "com.tencent.mobileqq",              // QQ
        "com.sina.weibo",
        "com.baidu.searchbox",
        "com.baidu.browser.apps",
        "com.alibaba.android.rimet",         // DingTalk
        "com.taobao.taobao",
        "com.tmall.wireless",
        "com.eg.android.AlipayGphone",       // Alipay
        "com.UCMobile",                      // UC Browser
        "cn.wps.moffice",

        // === INTERNATIONAL CARRIERS ===
        "uk.co.ee.myee",
        "com.skt.prod.dialer",               // SK Telecom
        "com.sktelecom.minit",
        "com.kt.ollehusimmanager",

        // === NIELSEN/COMSCORE MEASUREMENT ===
        "com.nielsen.app.sdk",

        // === YANDEX ===
        "com.yandex.android",

        // === S23 AUDIT - MEDIUM RISK MISSING ===
        "com.samsung.android.callassistant", // Call transcription capabilities
        "com.sec.spp.push",                  // AD_ID access, app usage tracking
        "com.samsung.android.photoremasterservice", // Scans ALL gallery photos
        "com.samsung.videoscan",             // Scans all videos
        "com.samsung.mediasearch",           // Media content analysis with AI
        "com.samsung.android.mydevice",      // Device registration
        "com.mygalaxy.service",              // Marketing tracking
        "com.google.android.appsearch.apk",  // App search metadata sent to Google
        "com.google.android.apps.aiwallpapers", // Requires account, sends prompts to Google
        "com.google.android.apps.carrier.carrierwifi", // IMSI exposure potential
        "com.sec.imslogger",                 // VoLTE/VoWiFi call signaling logging
        "com.samsung.sdm",                   // Samsung device management
        "com.samsung.android.kmxservice",    // Knox MDM extension
        "com.qti.qcc",                       // Qualcomm - limited docs
        "com.samsung.android.mcfds",         // Multi-device continuity
        "com.samsung.android.mcfserver",     // Multi-device server
        "com.samsung.android.dsms",          // Data stream management
        "com.samsung.android.dbsc",          // Device-based service consent
        "com.samsung.android.singletake.service", // Camera AI
        "com.samsung.android.cidmanager",    // Carrier ID manager
        "com.samsung.android.mocca",         // Diagnostic tool
    )

    // Low risk packages - minimal concern, mostly bloatware
    private val LOW_RISK_PACKAGES = setOf(
        // =========================================================================
        // LOW RISK: Unnecessary bloatware, minimal privacy impact
        // Source: UAD-NG
        // =========================================================================

        // === SAMSUNG MISC ===
        "com.samsung.android.app.ledbackcover",
        "com.samsung.android.drivelink.stub",
        "com.samsung.android.mateagent",
        "com.sec.android.easyonehand",
        "com.samsung.android.wallpaper.res",

        // === GOOGLE MISC ===
        "com.google.android.marvin.talkback",
        "com.google.vr.vrcore",
        "com.google.android.printservice.recommendation",

        // === CARRIER STUBS ===
        "com.tmobile.rsuapp",
        "com.tmobile.rsusrv",
        "com.vzw.apnlib",

        // === INTERNATIONAL CARRIERS ===
        "jp.co.nttdocomo",
        "jp.softbank",
    )

    // Dangerous permission combinations (from NSA implant analysis)
    private val SURVEILLANCE_PERMISSIONS = listOf(
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.RECEIVE_BOOT_COMPLETED",
    )

    // =========================================================================
    // MAIN SCAN API
    // =========================================================================

    private const val TAG = "SovereigntyScanner"

    /**
     * Run comprehensive sovereignty scan.
     *
     * Returns a SovereigntyReport with:
     * - Sovereignty score (0-100, higher = more sovereign)
     * - List of detected threats
     * - Security configuration issues
     * - Recommended actions
     * - Device status (ROM, bootloader, root)
     * - Network status (VPN, MITM certs, WiFi security)
     */
    fun scan(context: Context): SovereigntyReport {
        Log.d(TAG, "Starting sovereignty scan...")
        val threats = mutableListOf<Threat>()

        // 1. Scan for known surveillance packages
        val bloatwareResult = scanForBloatware(context)
        Log.d(TAG, "Bloatware scan: found ${bloatwareResult.activeThreats.size} active threats, ${bloatwareResult.allPackageStates.size} packages tracked")
        threats.addAll(bloatwareResult.activeThreats)

        // 2. Check accessibility services (keylogger vector)
        val accessibilityThreats = scanAccessibilityServices(context)
        Log.d(TAG, "Accessibility scan: found ${accessibilityThreats.size} threats")
        threats.addAll(accessibilityThreats)

        // 3. Check for device admin apps (MDM control)
        val adminThreats = scanDeviceAdmins(context)
        Log.d(TAG, "Device admin scan: found ${adminThreats.size} threats")
        threats.addAll(adminThreats)

        // 4. Check user CA certificates (MITM vector)
        val certThreats = scanUserCertificates()
        Log.d(TAG, "Certificate scan: found ${certThreats.size} threats")
        threats.addAll(certThreats)

        // 5. Check security configuration
        val configThreats = scanSecurityConfig(context)
        Log.d(TAG, "Config scan: found ${configThreats.size} threats")
        threats.addAll(configThreats)

        // 6. Scan for root/bootloader unlock
        val rootThreats = scanRootStatus()
        Log.d(TAG, "Root scan: found ${rootThreats.size} threats")
        threats.addAll(rootThreats)

        // 7. Check for suspicious apps with dangerous permission combos
        val permThreats = scanDangerousPermissions(context)
        Log.d(TAG, "Permission scan: found ${permThreats.size} threats")
        threats.addAll(permThreats)

        Log.d(TAG, "Total threats found: ${threats.size}")
        for (threat in threats) {
            Log.d(TAG, "  - ${threat.severity}: ${threat.id} (${threat.name})")
        }

        // Gather device status
        val deviceStatus = getDeviceStatus()

        // Gather network status
        val networkStatus = getNetworkStatus(context, certThreats.isNotEmpty())

        // Generate recommendations based on threats and status
        val recommendations = generateRecommendations(threats, deviceStatus, networkStatus)

        // Calculate legacy score (for backwards compatibility)
        val legacyScore = calculateScore(threats)
        Log.d(TAG, "Calculated legacy score: $legacyScore")

        // === NEW DUAL SCORE SYSTEM ===
        // Calculate sovereignty domain statuses (binary per domain)
        val domainStatuses = calculateDomainStatuses(threats)
        val sovereigntyScore = calculateSovereigntyScore(domainStatuses)
        Log.d(TAG, "Sovereignty score: $sovereigntyScore% (${domainStatuses.count { it.isSovereign }}/${domainStatuses.size} domains)")

        // Calculate privacy entity exposures (cumulative)
        val entityExposures = calculateEntityExposures(threats)
        val privacyScore = calculatePrivacyScore(entityExposures)
        val exposedCount = entityExposures.count { it.packages.isNotEmpty() }
        Log.d(TAG, "Privacy score: $privacyScore (exposed to $exposedCount entities)")

        return SovereigntyReport(
            score = legacyScore,
            threats = threats,
            timestamp = System.currentTimeMillis(),
            isSafe = sovereigntyScore >= 70 && threats.none { it.severity == ThreatSeverity.CRITICAL },
            deviceStatus = deviceStatus,
            networkStatus = networkStatus,
            recommendations = recommendations,
            packageStates = bloatwareResult.allPackageStates,
            // New dual score fields
            domainStatuses = domainStatuses,
            entityExposures = entityExposures,
            sovereigntyScore = sovereigntyScore,
            privacyScore = privacyScore
        )
    }

    /**
     * Quick check - only critical issues.
     * Use this before sensitive operations.
     */
    fun quickCheck(context: Context): Boolean {
        // Check most critical issues only
        val bloatwareResult = scanForBloatware(context)
        val hasRootkit = bloatwareResult.activeThreats.any {
            it.severity == ThreatSeverity.CRITICAL &&
            it.category == ThreatCategory.BACKDOOR
        }
        val hasMITM = scanUserCertificates().isNotEmpty()
        val hasKeylogger = scanAccessibilityServices(context).any {
            it.severity == ThreatSeverity.CRITICAL
        }

        return !hasRootkit && !hasMITM && !hasKeylogger
    }

    // =========================================================================
    // DETECTION MODULES
    // =========================================================================

    /**
     * Scan result containing the full picture of all known surveillance packages.
     */
    data class BloatwareScanResult(
        val activeThreats: List<Threat>,
        val allPackageStates: List<PackageSecurityState>
    )

    private fun scanForBloatware(context: Context): BloatwareScanResult {
        val pm = context.packageManager
        val threats = mutableListOf<Threat>()
        val allStates = mutableListOf<PackageSecurityState>()

        // Check ALL packages in our threat database, not just installed ones
        // Total: 400+ packages from research (Samsung, Google, carriers, SDKs, Chinese tech)
        val allKnownPackages = CRITICAL_PACKAGES + HIGH_RISK_PACKAGES + MEDIUM_RISK_PACKAGES + LOW_RISK_PACKAGES

        for (packageName in allKnownPackages) {
            val isCritical = packageName in CRITICAL_PACKAGES
            val isHigh = packageName in HIGH_RISK_PACKAGES
            val isMedium = packageName in MEDIUM_RISK_PACKAGES
            val severity = when {
                isCritical -> ThreatSeverity.CRITICAL
                isHigh -> ThreatSeverity.HIGH
                isMedium -> ThreatSeverity.MEDIUM
                else -> ThreatSeverity.LOW
            }

            // Try to get package info
            val packageInfo = try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(packageName, 0)
                }
            } catch (e: PackageManager.NameNotFoundException) {
                // Package not installed - this is the best state
                allStates.add(PackageSecurityState(
                    packageName = packageName,
                    name = packageName.substringAfterLast(".").replaceFirstChar { it.uppercase() },
                    severity = severity,
                    state = PackageState.NOT_INSTALLED,
                    category = categorizePackage(packageName)
                ))
                continue
            } catch (e: Exception) {
                continue
            }

            // Package is installed, check if enabled
            // Must use getApplicationEnabledSetting() to detect user-disabled packages
            // ApplicationInfo.enabled doesn't reflect pm disable-user state
            val enabledSetting = try {
                pm.getApplicationEnabledSetting(packageName)
            } catch (e: Exception) {
                PackageManager.COMPONENT_ENABLED_STATE_DEFAULT
            }

            val isDisabled = enabledSetting == PackageManager.COMPONENT_ENABLED_STATE_DISABLED ||
                            enabledSetting == PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER ||
                            enabledSetting == PackageManager.COMPONENT_ENABLED_STATE_DISABLED_UNTIL_USED

            val appName = getAppName(pm, packageName)

            if (isDisabled) {
                // Package is disabled
                Log.d(TAG, "Found disabled package: $packageName")
                allStates.add(PackageSecurityState(
                    packageName = packageName,
                    name = appName,
                    severity = severity,
                    state = PackageState.DISABLED,
                    category = categorizePackage(packageName)
                ))
            } else {
                // Package is active - it's a threat
                Log.d(TAG, "Found active threat: $packageName")
                allStates.add(PackageSecurityState(
                    packageName = packageName,
                    name = appName,
                    severity = severity,
                    state = PackageState.ACTIVE,
                    category = categorizePackage(packageName)
                ))

                // Also add to threats list for scoring
                val threatDescription = when {
                    isCritical -> getCriticalDescription(packageName)
                    isHigh -> getHighRiskDescription(packageName)
                    isMedium -> getMediumRiskDescription(packageName)
                    else -> getLowRiskDescription(packageName)
                }
                val threatRecommendation = when {
                    isCritical -> "Disable via ADB: pm disable-user --user 0 $packageName"
                    isHigh -> "Consider disabling or restricting permissions"
                    else -> "Review if this app is necessary"
                }
                threats.add(Threat(
                    id = packageName,
                    name = appName,
                    description = threatDescription,
                    severity = severity,
                    category = categorizePackage(packageName),
                    recommendation = threatRecommendation
                ))
            }
        }

        // Sort: Active first, then Disabled, then Not Installed
        // Within each group, Critical before High
        allStates.sortWith(compareBy(
            { it.state.ordinal },
            { if (it.severity == ThreatSeverity.CRITICAL) 0 else 1 }
        ))

        return BloatwareScanResult(threats, allStates)
    }

    private fun scanAccessibilityServices(context: Context): List<Threat> {
        val threats = mutableListOf<Threat>()
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
            ?: return threats

        val enabledServices = am.getEnabledAccessibilityServiceList(
            AccessibilityServiceInfo.FEEDBACK_ALL_MASK
        )

        for (service in enabledServices) {
            val serviceId = service.id
            val packageName = serviceId.substringBefore("/")

            // Skip known legitimate accessibility services
            if (isKnownLegitimateAccessibility(packageName)) continue

            threats.add(Threat(
                id = serviceId,
                name = service.resolveInfo.loadLabel(context.packageManager).toString(),
                description = "Accessibility service can read all screen content and keystrokes. " +
                    "This is the primary vector for keyloggers and screen scrapers.",
                severity = ThreatSeverity.CRITICAL,
                category = ThreatCategory.KEYLOGGER,
                recommendation = "Disable unless absolutely necessary: Settings > Accessibility"
            ))
        }

        return threats
    }

    private fun scanDeviceAdmins(context: Context): List<Threat> {
        val threats = mutableListOf<Threat>()
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
            ?: return threats

        val admins = dpm.activeAdmins ?: return threats

        for (admin in admins) {
            val packageName = admin.packageName

            // Skip Find My Device (common legitimate admin)
            if (packageName == "com.google.android.gms") continue

            threats.add(Threat(
                id = admin.flattenToString(),
                name = getAppName(context.packageManager, packageName),
                description = "Device admin can remotely wipe device, set password policies, " +
                    "and enforce enterprise control. Common MDM vector.",
                severity = ThreatSeverity.HIGH,
                category = ThreatCategory.MDM,
                recommendation = "Review and remove if not required for work: Settings > Security > Device Admin"
            ))
        }

        return threats
    }

    private fun scanUserCertificates(): List<Threat> {
        val threats = mutableListOf<Threat>()

        try {
            // Check for user-installed CA certificates
            val keyStore = KeyStore.getInstance("AndroidCAStore")
            keyStore.load(null)

            val aliases = keyStore.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                if (alias.startsWith("user:")) {
                    val cert = keyStore.getCertificate(alias) as? X509Certificate
                    threats.add(Threat(
                        id = alias,
                        name = cert?.subjectDN?.name ?: "Unknown Certificate",
                        description = "User CA certificate enables MITM attacks. " +
                            "All HTTPS traffic can be intercepted and decrypted.",
                        severity = ThreatSeverity.CRITICAL,
                        category = ThreatCategory.MITM,
                        recommendation = "Remove immediately unless required for work: " +
                            "Settings > Security > Encryption > Trusted Credentials > User"
                    ))
                }
            }
        } catch (e: Exception) {
            // Can't access keystore - not necessarily bad
        }

        return threats
    }

    private fun scanSecurityConfig(context: Context): List<Threat> {
        val threats = mutableListOf<Threat>()

        // Check USB debugging
        try {
            val adbEnabled = Settings.Global.getInt(
                context.contentResolver,
                Settings.Global.ADB_ENABLED,
                0
            ) == 1

            if (adbEnabled) {
                threats.add(Threat(
                    id = "usb_debugging",
                    name = "USB Debugging Enabled",
                    description = "USB debugging allows ADB access when connected to a computer. " +
                        "Physical access to device enables full control.",
                    severity = ThreatSeverity.MEDIUM,
                    category = ThreatCategory.CONFIG,
                    recommendation = "Disable when not actively developing"
                ))
            }
        } catch (e: Exception) { }

        // Check wireless ADB
        try {
            val wirelessAdb = Settings.Global.getInt(
                context.contentResolver,
                "adb_wifi_enabled",
                0
            ) == 1

            if (wirelessAdb) {
                threats.add(Threat(
                    id = "wireless_adb",
                    name = "Wireless ADB Enabled",
                    description = "CRITICAL: ADB accessible over network. Anyone on your WiFi " +
                        "can control your device without physical access.",
                    severity = ThreatSeverity.CRITICAL,
                    category = ThreatCategory.CONFIG,
                    recommendation = "DISABLE IMMEDIATELY: Settings > Developer Options > Wireless Debugging"
                ))
            }
        } catch (e: Exception) { }

        // Check unknown sources (legacy)
        try {
            val unknownSources = Settings.Secure.getInt(
                context.contentResolver,
                "install_non_market_apps",
                0
            ) == 1

            if (unknownSources) {
                threats.add(Threat(
                    id = "unknown_sources",
                    name = "Unknown Sources Enabled",
                    description = "Allows installation from untrusted sources globally.",
                    severity = ThreatSeverity.MEDIUM,
                    category = ThreatCategory.CONFIG,
                    recommendation = "Disable and use per-app install permission instead"
                ))
            }
        } catch (e: Exception) { }

        return threats
    }

    private fun scanRootStatus(): List<Threat> {
        val threats = mutableListOf<Threat>()

        // Check for su binary
        val suPaths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/data/adb/magisk",
        )

        val isRooted = suPaths.any { File(it).exists() }

        if (isRooted) {
            threats.add(Threat(
                id = "root_detected",
                name = "Root Access Detected",
                description = "Device is rooted. This enables powerful privacy tools but also " +
                    "increases attack surface. Malware with root can bypass all security.",
                severity = ThreatSeverity.MEDIUM,
                category = ThreatCategory.ROOT,
                recommendation = "Ensure root manager (Magisk) is up to date with app whitelisting"
            ))
        }

        // Check bootloader (if accessible via system property)
        try {
            val process = Runtime.getRuntime().exec("getprop ro.boot.verifiedbootstate")
            val result = process.inputStream.bufferedReader().readText().trim()

            if (result == "orange") {
                threats.add(Threat(
                    id = "bootloader_unlocked",
                    name = "Bootloader Unlocked",
                    description = "Bootloader is unlocked. Device can be flashed with modified firmware. " +
                        "Physical attacker could install persistent rootkit.",
                    severity = ThreatSeverity.HIGH,
                    category = ThreatCategory.BOOTLOADER,
                    recommendation = "Re-lock bootloader if not needed for custom ROM"
                ))
            }
        } catch (e: Exception) { }

        return threats
    }

    private fun scanDangerousPermissions(context: Context): List<Threat> {
        val threats = mutableListOf<Threat>()
        val pm = context.packageManager

        val packages = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            }
        } catch (e: Exception) {
            return threats
        }

        for (pkg in packages) {
            // Skip system apps and known packages
            if (pkg.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0) continue
            if (pkg.packageName in CRITICAL_PACKAGES || pkg.packageName in HIGH_RISK_PACKAGES) continue
            if (isKnownLegitimate(pkg.packageName)) continue

            val permissions = pkg.requestedPermissions ?: continue
            val hasInternet = permissions.any { it == "android.permission.INTERNET" }
            val hasBoot = permissions.any { it == "android.permission.RECEIVE_BOOT_COMPLETED" }

            if (!hasInternet) continue  // Can't exfiltrate without internet

            val surveillancePerms = permissions.filter { it in SURVEILLANCE_PERMISSIONS }

            // Flag apps with surveillance-capable permission combos
            val hasMic = "android.permission.RECORD_AUDIO" in surveillancePerms
            val hasCamera = "android.permission.CAMERA" in surveillancePerms
            val hasLocation = surveillancePerms.any { it.contains("LOCATION") }

            if (hasBoot && (hasMic || hasCamera || hasLocation)) {
                threats.add(Threat(
                    id = "suspicious_${pkg.packageName}",
                    name = getAppName(pm, pkg.packageName),
                    description = buildString {
                        append("Third-party app starts on boot with ")
                        if (hasMic) append("microphone, ")
                        if (hasCamera) append("camera, ")
                        if (hasLocation) append("location, ")
                        append("and internet access. Matches implant behavioral pattern.")
                    },
                    severity = ThreatSeverity.HIGH,
                    category = ThreatCategory.SUSPICIOUS_APP,
                    recommendation = "Review app necessity. Check with: ${pkg.packageName}"
                ))
            }
        }

        return threats
    }

    // =========================================================================
    // DEVICE & NETWORK STATUS
    // =========================================================================

    private fun getDeviceStatus(): DeviceStatus {
        val isRooted = checkRootStatus()
        val bootloaderStatus = checkBootloaderStatus()
        val customRomInfo = detectCustomRom()

        return DeviceStatus(
            isBootloaderUnlocked = bootloaderStatus,
            hasCustomRom = customRomInfo.first,
            isRooted = isRooted,
            romName = customRomInfo.second,
            androidVersion = Build.VERSION.RELEASE,
            securityPatchLevel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                Build.VERSION.SECURITY_PATCH
            } else {
                "Unknown"
            },
            deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}"
        )
    }

    private fun checkRootStatus(): Boolean {
        val suPaths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/data/adb/magisk",
        )
        return suPaths.any { File(it).exists() }
    }

    private fun checkBootloaderStatus(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("getprop ro.boot.verifiedbootstate")
            val result = process.inputStream.bufferedReader().readText().trim()
            result == "orange"
        } catch (e: Exception) {
            false
        }
    }

    private fun detectCustomRom(): Pair<Boolean, String?> {
        // Check for common custom ROM indicators
        val customRomProps = mapOf(
            "ro.lineage.version" to "LineageOS",
            "ro.lineage.build.version" to "LineageOS",
            "ro.cm.version" to "CyanogenMod",
            "ro.modversion" to "Custom ROM",
            "ro.carbon.version" to "Carbon ROM",
            "ro.pa.version" to "Paranoid Android",
            "ro.rr.version" to "Resurrection Remix",
            "ro.aicp.version" to "AICP",
            "ro.havoc.version" to "Havoc OS",
            "ro.potato.version" to "POSP",
            "ro.pixelexperience.version" to "Pixel Experience",
            "ro.evolution.version" to "Evolution X",
            "ro.arrow.version" to "Arrow OS",
            "ro.corvus.version" to "Corvus OS",
            "ro.crdroid.version" to "crDroid",
            "ro.grapheneos.version" to "GrapheneOS",
            "ro.calyxos.version" to "CalyxOS",
            "ro.divestos.version" to "DivestOS",
            "ro.e.version" to "/e/OS"
        )

        for ((prop, romName) in customRomProps) {
            try {
                val process = Runtime.getRuntime().exec("getprop $prop")
                val result = process.inputStream.bufferedReader().readText().trim()
                if (result.isNotEmpty()) {
                    return Pair(true, romName)
                }
            } catch (e: Exception) {
                // Continue checking
            }
        }

        // Check build fingerprint for non-stock indicators
        val fingerprint = Build.FINGERPRINT.lowercase()
        val display = Build.DISPLAY.lowercase()

        val customIndicators = listOf(
            "lineage", "cyanogen", "aosp", "carbon", "paranoid", "resurrection",
            "aicp", "havoc", "potato", "pixel experience", "evolution", "arrow",
            "corvus", "crdroid", "graphene", "calyx", "divest", "/e/"
        )

        for (indicator in customIndicators) {
            if (fingerprint.contains(indicator) || display.contains(indicator)) {
                return Pair(true, indicator.replaceFirstChar { it.uppercase() })
            }
        }

        // Check if build is user-debug or eng (indicates custom build)
        val buildType = Build.TYPE.lowercase()
        if (buildType == "userdebug" || buildType == "eng") {
            return Pair(true, "Custom Build ($buildType)")
        }

        return Pair(false, null)
    }

    private fun getNetworkStatus(context: Context, hasMitmCerts: Boolean): NetworkStatus {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        var hasVpn = false
        var vpnPackage: String? = null

        if (connectivityManager != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val activeNetwork = connectivityManager.activeNetwork
            val capabilities = activeNetwork?.let { connectivityManager.getNetworkCapabilities(it) }
            hasVpn = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }

        // Try to find VPN package
        if (hasVpn) {
            vpnPackage = detectActiveVpnPackage(context)
        }

        // Check WiFi security
        val wifiInfo = getWifiSecurityInfo(context)

        return NetworkStatus(
            hasVpnActive = hasVpn,
            hasMitmCertificates = hasMitmCerts,
            isWifiSecure = wifiInfo.first,
            vpnPackage = vpnPackage,
            wifiEncryption = wifiInfo.second
        )
    }

    private fun detectActiveVpnPackage(context: Context): String? {
        val pm = context.packageManager
        val knownVpns = listOf(
            "org.torproject.android" to "Orbot (Tor)",
            "net.mullvad.mullvadvpn" to "Mullvad VPN",
            "com.proton.vpn" to "Proton VPN",
            "de.blinkt.openvpn" to "OpenVPN",
            "com.wireguard.android" to "WireGuard",
            "ch.protonvpn.android" to "Proton VPN",
            "com.nordvpn.android" to "NordVPN",
            "com.expressvpn.vpn" to "ExpressVPN",
            "com.privateinternetaccess.android" to "PIA",
            "com.cloudflare.onedotonedotonedotone" to "Cloudflare WARP"
        )

        for ((packageName, displayName) in knownVpns) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(packageName, 0)
                }
                return displayName
            } catch (e: PackageManager.NameNotFoundException) {
                // Package not installed
            }
        }
        return "Unknown VPN"
    }

    @Suppress("DEPRECATION")
    private fun getWifiSecurityInfo(context: Context): Pair<Boolean, String?> {
        try {
            val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
                ?: return Pair(true, null)

            val connectionInfo = wifiManager.connectionInfo
            if (connectionInfo.networkId == -1) {
                return Pair(true, "Not connected")
            }

            // Check configured networks for security type
            val configuredNetworks = wifiManager.configuredNetworks ?: return Pair(true, "Unknown")

            for (network in configuredNetworks) {
                if (network.networkId == connectionInfo.networkId) {
                    val security = when {
                        network.allowedKeyManagement.get(android.net.wifi.WifiConfiguration.KeyMgmt.WPA_PSK) -> "WPA/WPA2"
                        network.allowedKeyManagement.get(android.net.wifi.WifiConfiguration.KeyMgmt.WPA_EAP) -> "WPA Enterprise"
                        network.allowedKeyManagement.get(android.net.wifi.WifiConfiguration.KeyMgmt.IEEE8021X) -> "802.1X"
                        network.allowedKeyManagement.get(android.net.wifi.WifiConfiguration.KeyMgmt.NONE) -> {
                            if (network.wepKeys[0] != null) "WEP (Insecure)" else "Open (Insecure)"
                        }
                        else -> "Unknown"
                    }
                    val isSecure = !security.contains("Insecure") && security != "Open (Insecure)"
                    return Pair(isSecure, security)
                }
            }
        } catch (e: Exception) {
            // Permission denied or other issue
        }
        return Pair(true, "Unknown")
    }

    private fun generateRecommendations(
        threats: List<Threat>,
        deviceStatus: DeviceStatus,
        networkStatus: NetworkStatus
    ): List<SecurityRecommendation> {
        val recommendations = mutableListOf<SecurityRecommendation>()

        // Critical: MITM certificates
        if (networkStatus.hasMitmCertificates) {
            recommendations.add(SecurityRecommendation(
                id = "remove_ca_certs",
                title = "Remove Untrusted Certificates",
                description = "User-installed CA certificates can intercept all HTTPS traffic. Remove them unless required for corporate environment.",
                priority = RecommendationPriority.CRITICAL
            ))
        }

        // Critical: Insecure WiFi
        if (!networkStatus.isWifiSecure) {
            recommendations.add(SecurityRecommendation(
                id = "secure_wifi",
                title = "Connect to Secure Network",
                description = "Current WiFi network uses weak or no encryption. Use a VPN or switch to a WPA2/WPA3 protected network.",
                priority = RecommendationPriority.CRITICAL
            ))
        }

        // High: No VPN on insecure network
        if (!networkStatus.hasVpnActive && !networkStatus.isWifiSecure) {
            recommendations.add(SecurityRecommendation(
                id = "enable_vpn",
                title = "Enable VPN Protection",
                description = "Use a trusted VPN to encrypt network traffic and protect against local eavesdropping.",
                priority = RecommendationPriority.HIGH
            ))
        }

        // High: Accessibility services enabled
        val keyloggerThreats = threats.filter { it.category == ThreatCategory.KEYLOGGER }
        if (keyloggerThreats.isNotEmpty()) {
            recommendations.add(SecurityRecommendation(
                id = "review_accessibility",
                title = "Review Accessibility Services",
                description = "Accessibility services can read all screen content. Disable unnecessary services in Settings > Accessibility.",
                priority = RecommendationPriority.HIGH
            ))
        }

        // High: Backdoor apps detected
        val backdoorThreats = threats.filter { it.category == ThreatCategory.BACKDOOR }
        if (backdoorThreats.isNotEmpty()) {
            recommendations.add(SecurityRecommendation(
                id = "remove_backdoors",
                title = "Disable Silent Installers",
                description = "Apps with silent install capability can add software without consent. Disable via ADB or restrict permissions.",
                priority = RecommendationPriority.HIGH
            ))
        }

        // Medium: Root without proper management
        if (deviceStatus.isRooted) {
            recommendations.add(SecurityRecommendation(
                id = "secure_root",
                title = "Secure Root Access",
                description = "Ensure root manager is up to date and configure app-level root access controls. Deny root to untrusted apps.",
                priority = RecommendationPriority.MEDIUM
            ))
        }

        // Medium: Unlocked bootloader awareness
        if (deviceStatus.isBootloaderUnlocked && !deviceStatus.hasCustomRom) {
            recommendations.add(SecurityRecommendation(
                id = "bootloader_awareness",
                title = "Bootloader Security Notice",
                description = "Unlocked bootloader allows firmware modification. Physical device access could enable persistent compromises.",
                priority = RecommendationPriority.MEDIUM
            ))
        }

        // Medium: Always-listening services
        val listeningThreats = threats.filter { it.category == ThreatCategory.ALWAYS_LISTENING }
        if (listeningThreats.isNotEmpty()) {
            recommendations.add(SecurityRecommendation(
                id = "disable_voice_assistants",
                title = "Disable Voice Assistants",
                description = "Always-listening services keep the microphone active. Disable wake word detection for privacy.",
                priority = RecommendationPriority.MEDIUM
            ))
        }

        // Low: Outdated security patch
        if (deviceStatus.securityPatchLevel != "Unknown") {
            try {
                val patchDate = java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US)
                    .parse(deviceStatus.securityPatchLevel)
                val sixMonthsAgo = System.currentTimeMillis() - (180L * 24 * 60 * 60 * 1000)
                if (patchDate != null && patchDate.time < sixMonthsAgo) {
                    recommendations.add(SecurityRecommendation(
                        id = "update_security_patch",
                        title = "Security Patch Outdated",
                        description = "Device security patch is more than 6 months old. Check for system updates.",
                        priority = RecommendationPriority.MEDIUM
                    ))
                }
            } catch (e: Exception) {
                // Could not parse date
            }
        }

        // Positive: Custom ROM with good privacy
        if (deviceStatus.hasCustomRom) {
            val privacyRoms = listOf("GrapheneOS", "CalyxOS", "DivestOS", "LineageOS")
            if (privacyRoms.any { deviceStatus.romName?.contains(it, ignoreCase = true) == true }) {
                recommendations.add(SecurityRecommendation(
                    id = "privacy_rom_detected",
                    title = "Privacy-Focused ROM Detected",
                    description = "Running ${deviceStatus.romName} provides enhanced privacy controls. Ensure you're using the latest version.",
                    priority = RecommendationPriority.LOW,
                    actionable = false
                ))
            }
        }

        return recommendations.sortedBy { it.priority.ordinal }
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    /**
     * Calculate sovereignty score using weighted category-based scoring.
     *
     * The scoring algorithm matches the PC sovereignty-scanner:
     * 1. Group threats by category
     * 2. Apply diminishing returns within each category (first threat in a category
     *    hurts more than subsequent ones)
     * 3. Cap maximum penalty per category to prevent single category from tanking score
     * 4. Ensure score reflects actual risk, not just bloatware count
     *
     * This prevents a stock phone with many Samsung/Google packages from showing 0
     * while still penalizing truly dangerous configurations.
     */
    private fun calculateScore(threats: List<Threat>): Int {
        if (threats.isEmpty()) {
            return 100
        }

        // Group threats by category for weighted scoring
        val threatsByCategory = threats.groupBy { it.category }

        var totalPenalty = 0.0

        for ((category, categoryThreats) in threatsByCategory) {
            // Base penalty per category (first threat)
            val basePenalty = when (category) {
                ThreatCategory.MITM -> 30.0        // MITM is catastrophic
                ThreatCategory.KEYLOGGER -> 25.0  // Keyloggers are critical
                ThreatCategory.BACKDOOR -> 20.0   // Silent installers are serious
                ThreatCategory.MDM -> 15.0        // MDM indicates corporate control
                ThreatCategory.ALWAYS_LISTENING -> 12.0
                ThreatCategory.BIOMETRICS -> 10.0
                ThreatCategory.LOCATION -> 8.0
                ThreatCategory.SURVEILLANCE -> 6.0
                ThreatCategory.ANALYTICS -> 4.0
                ThreatCategory.CARRIER -> 4.0
                ThreatCategory.CONFIG -> 5.0
                ThreatCategory.ROOT -> 3.0        // Root is neutral-ish
                ThreatCategory.BOOTLOADER -> 3.0  // Same for bootloader
                ThreatCategory.SUSPICIOUS_APP -> 8.0
            }

            // Cap per category to prevent excessive penalty from bloatware
            val maxCategoryPenalty = when (category) {
                ThreatCategory.MITM -> 30.0       // No cap - each MITM cert is bad
                ThreatCategory.KEYLOGGER -> 30.0  // No cap - each keylogger is bad
                ThreatCategory.BACKDOOR -> 25.0
                ThreatCategory.MDM -> 20.0
                ThreatCategory.ALWAYS_LISTENING -> 15.0  // Multiple voice assistants = one problem
                ThreatCategory.BIOMETRICS -> 12.0
                ThreatCategory.LOCATION -> 10.0
                ThreatCategory.SURVEILLANCE -> 15.0
                ThreatCategory.ANALYTICS -> 10.0   // Cap analytics bloat
                ThreatCategory.CARRIER -> 8.0      // Carrier bloat is common
                ThreatCategory.CONFIG -> 15.0
                ThreatCategory.ROOT -> 5.0
                ThreatCategory.BOOTLOADER -> 5.0
                ThreatCategory.SUSPICIOUS_APP -> 20.0
            }

            // Calculate penalty with diminishing returns
            // First threat: 100% of base penalty
            // Second threat: 50% of base penalty
            // Third threat: 25% of base penalty
            // etc.
            var categoryPenalty = 0.0
            for ((index, threat) in categoryThreats.sortedByDescending { it.severity }.withIndex()) {
                val severityMultiplier = when (threat.severity) {
                    ThreatSeverity.CRITICAL -> 1.5
                    ThreatSeverity.HIGH -> 1.0
                    ThreatSeverity.MEDIUM -> 0.5
                    ThreatSeverity.LOW -> 0.25
                }
                // Diminishing returns: each subsequent threat contributes less
                val diminishingFactor = 1.0 / (index + 1)
                categoryPenalty += basePenalty * severityMultiplier * diminishingFactor
            }

            // Apply category cap
            categoryPenalty = minOf(categoryPenalty, maxCategoryPenalty)
            totalPenalty += categoryPenalty

            Log.d(TAG, "Category $category: ${categoryThreats.size} threats, penalty: $categoryPenalty (capped at $maxCategoryPenalty)")
        }

        // Apply overall cap - score can't go below 5 unless truly catastrophic
        // (MITM + keylogger + backdoor all present)
        val hasCatastrophicCombo = threatsByCategory.containsKey(ThreatCategory.MITM) &&
                                   threatsByCategory.containsKey(ThreatCategory.KEYLOGGER)

        val minScore = if (hasCatastrophicCombo) 0 else 5
        val finalScore = maxOf(minScore, (100 - totalPenalty).toInt())

        Log.d(TAG, "Score calculation: totalPenalty=$totalPenalty, minScore=$minScore, finalScore=$finalScore")

        return finalScore
    }

    private fun getAppName(pm: PackageManager, packageName: String): String {
        return try {
            val appInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getApplicationInfo(packageName, 0)
            }
            pm.getApplicationLabel(appInfo).toString()
        } catch (e: Exception) {
            packageName.substringAfterLast(".")
        }
    }

    private fun categorizePackage(packageName: String): ThreatCategory {
        return when {
            // Backdoors / Silent installers
            packageName.contains("dti") || packageName.contains("aura") ||
                packageName.contains("appmanager") || packageName.contains("ignite") ||
                packageName.contains("appcloud") || packageName.contains("preloadinstaller") ||
                packageName == "com.carrieriq.iqagent" || packageName == "com.att.iqi" -> ThreatCategory.BACKDOOR

            // Always listening / Voice assistants
            packageName.contains("bixby.wakeup") || packageName.contains("hotword") ||
                packageName.contains("voicewakeup") || packageName.contains("svoice") -> ThreatCategory.ALWAYS_LISTENING

            // Biometrics / Face recognition
            packageName.contains("face") || packageName.contains("iris") ||
                packageName.contains("biometrics") || packageName.contains("aremoji") -> ThreatCategory.BIOMETRICS

            // Location tracking
            packageName.contains("location") || packageName.contains("geofence") ||
                packageName.contains("llkagent") || packageName.contains("fmm") ||
                packageName.contains("safegraph") || packageName.contains("xmode") ||
                packageName.contains("veraset") || packageName.contains("cuebiq") ||
                packageName.contains("gravy") || packageName.contains("positioning") -> ThreatCategory.LOCATION

            // Analytics / Telemetry
            packageName.contains("analytics") || packageName.contains("telemetry") ||
                packageName.contains("firebase") || packageName.contains("crashlytics") ||
                packageName.contains("appsflyer") || packageName.contains("adjust") ||
                packageName.contains("branch") || packageName.contains("mixpanel") ||
                packageName.contains("amplitude") || packageName.contains("segment") ||
                packageName.contains("flurry") || packageName.contains("comscore") ||
                packageName.contains("wellbeing") || packageName.contains("usage") -> ThreatCategory.ANALYTICS

            // Carrier bloatware
            packageName.contains("vzw") || packageName.contains("verizon") ||
                packageName.contains("att.") || packageName.contains("tmobile") ||
                packageName.contains("sprint") || packageName.contains("carrier") ||
                packageName.contains("skt") || packageName.contains("docomo") -> ThreatCategory.CARRIER

            // MDM / Enterprise control
            packageName.contains("knox") || packageName.contains("mdm") ||
                packageName.contains("enterprise") || packageName.contains("supervision") -> ThreatCategory.MDM

            // General surveillance (Facebook, Google, Chinese tech, session recording)
            packageName.contains("facebook") || packageName.contains("instagram") ||
                packageName.contains("tiktok") || packageName.contains("musically") ||
                packageName.contains("tencent") || packageName.contains("baidu") ||
                packageName.contains("alibaba") || packageName.contains("fullstory") ||
                packageName.contains("smartlook") || packageName.contains("uxcam") ||
                packageName.contains("jiguang") || packageName.contains("jpush") ||
                packageName.contains("umeng") -> ThreatCategory.SURVEILLANCE

            else -> ThreatCategory.SURVEILLANCE
        }
    }

    // =========================================================================
    // DUAL SCORE SYSTEM - Sovereignty Domains & Privacy Entities
    // =========================================================================

    /**
     * Map a ThreatCategory to the SovereigntyDomain it compromises.
     */
    private fun mapCategoryToDomain(category: ThreatCategory): SovereigntyDomain {
        return when (category) {
            ThreatCategory.LOCATION -> SovereigntyDomain.LOCATION
            ThreatCategory.ALWAYS_LISTENING -> SovereigntyDomain.AUDIO
            ThreatCategory.BIOMETRICS -> SovereigntyDomain.VISUAL
            ThreatCategory.SURVEILLANCE -> SovereigntyDomain.IDENTITY  // General surveillance compromises identity
            ThreatCategory.ANALYTICS -> SovereigntyDomain.IDENTITY     // Analytics = profiling = identity
            ThreatCategory.CARRIER -> SovereigntyDomain.COMMUNICATIONS // Carriers intercept comms
            ThreatCategory.KEYLOGGER -> SovereigntyDomain.COMMUNICATIONS
            ThreatCategory.MDM -> SovereigntyDomain.DEVICE_CONTROL
            ThreatCategory.BACKDOOR -> SovereigntyDomain.DEVICE_CONTROL
            ThreatCategory.MITM -> SovereigntyDomain.NETWORK
            ThreatCategory.CONFIG -> SovereigntyDomain.NETWORK
            ThreatCategory.ROOT -> SovereigntyDomain.DEVICE_CONTROL
            ThreatCategory.BOOTLOADER -> SovereigntyDomain.DEVICE_CONTROL
            ThreatCategory.SUSPICIOUS_APP -> SovereigntyDomain.IDENTITY
        }
    }

    /**
     * Detect which privacy entity a package sends data to.
     */
    private fun detectEntity(packageName: String): PrivacyEntity? {
        val pkg = packageName.lowercase()
        return when {
            // Google
            pkg.contains("google") || pkg.contains("gms") || pkg.contains("gsf") ||
            pkg.contains("android.as") || pkg.contains("aicore") -> PrivacyEntity.GOOGLE

            // Samsung
            pkg.contains("samsung") || pkg.contains("sec.android") ||
            pkg.contains("scloud") || pkg.contains("bixby") || pkg.contains("knox") -> PrivacyEntity.SAMSUNG

            // Qualcomm
            pkg.contains("qualcomm") || pkg.contains("qti.") || pkg.contains("qcom") -> PrivacyEntity.QUALCOMM

            // Meta (Facebook)
            pkg.contains("facebook") || pkg.contains("instagram") ||
            pkg.contains("whatsapp") || pkg.contains("meta.") -> PrivacyEntity.META

            // Amazon
            pkg.contains("amazon") || pkg.contains("audible") || pkg.contains("kindle") -> PrivacyEntity.AMAZON

            // Microsoft
            pkg.contains("microsoft") || pkg.contains("skype") ||
            pkg.contains("linkedin") || pkg.contains("swiftkey") -> PrivacyEntity.MICROSOFT

            // Carrier
            pkg.contains("verizon") || pkg.contains("vzw") || pkg.contains("att.") ||
            pkg.contains("tmobile") || pkg.contains("sprint") || pkg.contains("carrier") ||
            pkg.contains("docomo") || pkg.contains("vodafone") -> PrivacyEntity.CARRIER

            // Chinese Tech
            pkg.contains("tencent") || pkg.contains("baidu") || pkg.contains("alibaba") ||
            pkg.contains("jiguang") || pkg.contains("jpush") || pkg.contains("umeng") ||
            pkg.contains("xiaomi") || pkg.contains("miui") || pkg.contains("huawei") ||
            pkg.contains("oppo") || pkg.contains("vivo") || pkg.contains("tiktok") ||
            pkg.contains("bytedance") -> PrivacyEntity.CHINESE_TECH

            // Third-party trackers
            pkg.contains("appsflyer") || pkg.contains("adjust") || pkg.contains("branch") ||
            pkg.contains("segment") || pkg.contains("mixpanel") || pkg.contains("amplitude") ||
            pkg.contains("flurry") || pkg.contains("comscore") || pkg.contains("firebase") ||
            pkg.contains("crashlytics") || pkg.contains("fullstory") || pkg.contains("smartlook") ||
            pkg.contains("uxcam") || pkg.contains("safegraph") || pkg.contains("xmode") ||
            pkg.contains("cuebiq") || pkg.contains("gravy") || pkg.contains("dti.") ||
            pkg.contains("aura.oobe") || pkg.contains("ironsource") ||
            pkg.contains("threatmetrix") || pkg.contains("iovation") -> PrivacyEntity.THIRD_PARTY_TRACKER

            else -> null
        }
    }

    /**
     * Determine what data types a package likely collects based on its name/category.
     */
    private fun getDataTypes(packageName: String, category: ThreatCategory): Set<String> {
        val types = mutableSetOf<String>()
        val pkg = packageName.lowercase()

        // Based on category
        when (category) {
            ThreatCategory.LOCATION -> types.add("location")
            ThreatCategory.ALWAYS_LISTENING -> types.addAll(listOf("audio", "voice"))
            ThreatCategory.BIOMETRICS -> types.addAll(listOf("biometrics", "face", "fingerprint"))
            ThreatCategory.ANALYTICS -> types.addAll(listOf("usage", "behavior"))
            ThreatCategory.CARRIER -> types.addAll(listOf("calls", "sms", "location"))
            ThreatCategory.KEYLOGGER -> types.add("keystrokes")
            ThreatCategory.MDM -> types.add("device_control")
            ThreatCategory.BACKDOOR -> types.add("app_install")
            ThreatCategory.SURVEILLANCE -> types.add("behavior")
            else -> {}
        }

        // Based on package name patterns
        if (pkg.contains("contact")) types.add("contacts")
        if (pkg.contains("calendar")) types.add("calendar")
        if (pkg.contains("sms") || pkg.contains("messaging")) types.add("sms")
        if (pkg.contains("call") || pkg.contains("dialer")) types.add("calls")
        if (pkg.contains("camera") || pkg.contains("photo")) types.add("photos")
        if (pkg.contains("cloud") || pkg.contains("sync")) types.add("cloud_sync")
        if (pkg.contains("browser") || pkg.contains("chrome")) types.add("browsing")

        return types
    }

    /**
     * Calculate sovereignty domain statuses from threats.
     */
    private fun calculateDomainStatuses(threats: List<Threat>): List<DomainStatus> {
        val domainThreats = mutableMapOf<SovereigntyDomain, MutableList<String>>()

        // Initialize all domains
        SovereigntyDomain.values().forEach { domain ->
            domainThreats[domain] = mutableListOf()
        }

        // Map each threat to its domain
        for (threat in threats) {
            val domain = mapCategoryToDomain(threat.category)
            domainThreats[domain]?.add(threat.name)
        }

        return SovereigntyDomain.values().map { domain ->
            val compromisedBy = domainThreats[domain] ?: emptyList()
            DomainStatus(
                domain = domain,
                isSovereign = compromisedBy.isEmpty(),
                compromisedBy = compromisedBy
            )
        }
    }

    /**
     * Calculate privacy entity exposures from detected packages.
     */
    private fun calculateEntityExposures(threats: List<Threat>): List<EntityExposure> {
        val entityPackages = mutableMapOf<PrivacyEntity, MutableList<String>>()
        val entityDataTypes = mutableMapOf<PrivacyEntity, MutableSet<String>>()

        // Initialize all entities
        PrivacyEntity.values().forEach { entity ->
            entityPackages[entity] = mutableListOf()
            entityDataTypes[entity] = mutableSetOf()
        }

        // Map each threat to its entity
        for (threat in threats) {
            val entity = detectEntity(threat.id) ?: continue
            entityPackages[entity]?.add(threat.id)
            entityDataTypes[entity]?.addAll(getDataTypes(threat.id, threat.category))
        }

        return PrivacyEntity.values().map { entity ->
            EntityExposure(
                entity = entity,
                packages = entityPackages[entity] ?: emptyList(),
                dataTypes = entityDataTypes[entity] ?: emptySet()
            )
        }
    }

    /**
     * Calculate sovereignty score: percentage of domains that are sovereign.
     */
    private fun calculateSovereigntyScore(domainStatuses: List<DomainStatus>): Int {
        if (domainStatuses.isEmpty()) return 100
        val sovereignCount = domainStatuses.count { it.isSovereign }
        return (sovereignCount * 100) / domainStatuses.size
    }

    /**
     * Calculate privacy score: inverse of entity exposure.
     * 100 = no entities have your data
     * 0 = all entities have extensive access
     */
    private fun calculatePrivacyScore(entityExposures: List<EntityExposure>): Int {
        val exposedEntities = entityExposures.count { it.packages.isNotEmpty() }
        val totalEntities = entityExposures.size

        if (totalEntities == 0) return 100

        // Base score from entity count (each exposed entity reduces score)
        val entityPenalty = (exposedEntities * 100) / totalEntities

        // Additional penalty for heavy exposure (many packages per entity)
        val totalPackages = entityExposures.sumOf { it.packages.size }
        val packagePenalty = minOf(totalPackages * 2, 30) // Cap at 30

        return maxOf(0, 100 - entityPenalty - packagePenalty)
    }

    private fun getCriticalDescription(packageName: String): String {
        return when {
            packageName.contains("bixby.wakeup") || packageName.contains("hotword") ->
                "Always-listening service. Microphone constantly active for wake word detection."
            packageName.contains("face") || packageName.contains("iris") ->
                "Biometric data collection. Captures facial geometry or iris patterns."
            packageName.contains("dti") || packageName.contains("aura") ->
                "BACKDOOR: Silent app installer. Can install apps without your consent."
            packageName.contains("facebook.appmanager") || packageName.contains("facebook.system") ->
                "BACKDOOR: System-level Facebook installer with elevated privileges."
            packageName.contains("location.history") ->
                "Records ALL locations with timestamps. Sent to remote servers."
            packageName.contains("aicore") || packageName.contains("rubin") ->
                "AI behavioral profiling. Learns and predicts your actions."
            packageName == "com.att.iqi" ->
                "ROOTKIT: Carrier IQ - logs keystrokes, location, calls. 2011 scandal revealed massive surveillance."
            else -> "Critical surveillance capability detected."
        }
    }

    private fun getHighRiskDescription(packageName: String): String {
        return when {
            packageName.contains("analytics") || packageName.contains("dqagent") ->
                "Device telemetry and usage analytics sent to remote servers."
            packageName.contains("swiftkey") || packageName.contains("gboard") || packageName.contains("honeyboard") ->
                "Keyboard app with cloud sync. Can log all typed text."
            packageName.contains("facebook") || packageName.contains("instagram") ->
                "Meta surveillance ecosystem. Extensive tracking and profiling."
            packageName.contains("carrier") || packageName.contains("vzw") || packageName.contains("verizon") ->
                "Carrier surveillance. Collects call metadata and usage patterns."
            packageName.contains("att") || packageName.contains("tmobile") || packageName.contains("sprint") ->
                "Carrier surveillance. Collects call metadata and usage patterns."
            packageName.contains("gms") || packageName.contains("gsf") ->
                "Google core services. Extensive tracking and data collection."
            packageName.contains("knox") || packageName.contains("mdm") ->
                "Enterprise device management. Remote control capability."
            packageName.contains("fmm") || packageName.contains("find") ->
                "Device tracking service. Reports location remotely."
            packageName.contains("update") || packageName.contains("omcagent") ->
                "Update service that can reinstall disabled packages."
            else -> "High-risk surveillance capability."
        }
    }

    private fun getMediumRiskDescription(packageName: String): String {
        return when {
            packageName.contains("bixby") ->
                "Samsung assistant. Potential voice data collection."
            packageName.contains("pay") || packageName.contains("samsungpass") ->
                "Payment/credential service. Handles sensitive data."
            packageName.contains("samsungapps") || packageName.contains("themestore") ->
                "Samsung app store. Can install apps automatically."
            packageName.contains("oneconnect") || packageName.contains("smartthings") ->
                "IoT hub. Connected home device data collection."
            packageName.contains("lool") || packageName.contains("devicecare") ->
                "Device Care uses Qihoo 360 (Chinese company) for junk cleaning."
            packageName.contains("youtube") || packageName.contains("gm") ->
                "Google app with data sync and viewing history tracking."
            packageName.contains("game.gos") ->
                "Game Optimizer. Known to throttle device performance."
            packageName.contains("vvm") ->
                "Visual voicemail. Processes call data through carrier servers."
            packageName.contains("huawei") ->
                "Huawei service. May send data to Chinese servers."
            packageName.contains("xiaomi") || packageName.contains("miui") ->
                "Xiaomi/MIUI service. Known telemetry concerns."
            packageName.contains("crashlytics") || packageName.contains("bugsnag") || packageName.contains("sentry") ->
                "Crash reporting SDK. Sends device info and crash logs."
            packageName.contains("onesignal") || packageName.contains("urbanairship") ->
                "Push notification service. Tracks engagement metrics."
            packageName.contains("tencent") || packageName.contains("baidu") || packageName.contains("alibaba") ->
                "Chinese tech platform. Data may be shared with Chinese entities."
            else -> "Medium risk - review if necessary for your usage."
        }
    }

    private fun getLowRiskDescription(packageName: String): String {
        return when {
            packageName.contains("talkback") ->
                "Accessibility service. Safe for users who need it."
            packageName.contains("vr") ->
                "VR service. May collect usage data when active."
            packageName.contains("print") ->
                "Print service. Minimal privacy impact."
            packageName.contains("carrier") || packageName.contains("rsu") ->
                "Carrier utility. Minimal functionality."
            else -> "Low risk bloatware. Can be safely disabled if unused."
        }
    }

    private fun isKnownLegitimateAccessibility(packageName: String): Boolean {
        // Legitimate accessibility services
        return packageName in setOf(
            "com.google.android.marvin.talkback",  // TalkBack
            "com.samsung.accessibility",
            "com.android.switchaccess",
            "com.android.talkback",
        )
    }

    private fun isKnownLegitimate(packageName: String): Boolean {
        // Apps where surveillance permissions are expected
        return packageName in setOf(
            "org.thoughtcrime.securesms",  // Signal
            "org.telegram.messenger",
            "com.whatsapp",
            "com.google.android.dialer",
            "com.samsung.android.dialer",
            "com.sec.android.app.camera",
            "com.google.android.GoogleCamera",
        )
    }
}

// =========================================================================
// DATA CLASSES
// =========================================================================

data class SovereigntyReport(
    val score: Int,                    // Legacy score for backwards compatibility
    val threats: List<Threat>,
    val timestamp: Long,
    val isSafe: Boolean,
    val deviceStatus: DeviceStatus = DeviceStatus(),
    val networkStatus: NetworkStatus = NetworkStatus(),
    val recommendations: List<SecurityRecommendation> = emptyList(),
    val packageStates: List<PackageSecurityState> = emptyList(),
    // === NEW DUAL SCORE SYSTEM ===
    val domainStatuses: List<DomainStatus> = emptyList(),     // Binary sovereignty per domain
    val entityExposures: List<EntityExposure> = emptyList(),  // Privacy exposure by entity
    val sovereigntyScore: Int = 0,    // Domains sovereign / total domains (percentage)
    val privacyScore: Int = 0         // Inverse of entity exposure (100 = no exposure)
) {
    /** Number of domains where user is sovereign */
    val sovereignDomainCount: Int get() = domainStatuses.count { it.isSovereign }

    /** Total number of domains assessed */
    val totalDomains: Int get() = domainStatuses.size

    /** Number of entities with access to user's data */
    val exposedEntityCount: Int get() = entityExposures.count { it.packages.isNotEmpty() }

    /** Total packages sending data to external entities */
    val totalExposurePackages: Int get() = entityExposures.sumOf { it.packages.size }
}

/**
 * Represents the security state of a known surveillance package.
 * This gives users full visibility into what's on their device.
 */
data class PackageSecurityState(
    val packageName: String,
    val name: String,
    val severity: ThreatSeverity,  // How dangerous this package is when active
    val state: PackageState,        // Current state on device
    val category: ThreatCategory
)

/**
 * The three possible states for a surveillance package:
 * - ACTIVE: Installed and running - this is a threat
 * - DISABLED: Installed but can't run - neutralized but can be re-enabled by OTA
 * - NOT_INSTALLED: Not on device - best security state
 */
enum class PackageState {
    ACTIVE,         // Installed and enabled - THREAT
    DISABLED,       // Installed but disabled - neutralized
    NOT_INSTALLED   // Not on device - secure
}

data class DeviceStatus(
    val isBootloaderUnlocked: Boolean = false,
    val hasCustomRom: Boolean = false,
    val isRooted: Boolean = false,
    val romName: String? = null,
    val androidVersion: String = "",
    val securityPatchLevel: String = "",
    val deviceModel: String = ""
)

data class NetworkStatus(
    val hasVpnActive: Boolean = false,
    val hasMitmCertificates: Boolean = false,
    val isWifiSecure: Boolean = true,
    val vpnPackage: String? = null,
    val wifiEncryption: String? = null
)

data class SecurityRecommendation(
    val id: String,
    val title: String,
    val description: String,
    val priority: RecommendationPriority,
    val actionable: Boolean = true
)

enum class RecommendationPriority {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW
}

data class Threat(
    val id: String,
    val name: String,
    val description: String,
    val severity: ThreatSeverity,
    val category: ThreatCategory,
    val recommendation: String
)

enum class ThreatSeverity {
    CRITICAL,  // Immediate action required - active surveillance
    HIGH,      // Significant risk - tracking/analytics
    MEDIUM,    // Potential risk - misconfiguration
    LOW        // Minor concern - bloatware
}

enum class ThreatCategory {
    BACKDOOR,           // Silent installers
    ALWAYS_LISTENING,   // Microphone always on
    BIOMETRICS,         // Face/fingerprint collection
    LOCATION,           // Location tracking
    SURVEILLANCE,       // General surveillance
    ANALYTICS,          // Telemetry/tracking
    CARRIER,            // Carrier bloatware
    KEYLOGGER,          // Accessibility-based keyloggers
    MDM,                // Mobile device management
    MITM,               // Man-in-the-middle (CA certs)
    CONFIG,             // Security misconfiguration
    ROOT,               // Root detection
    BOOTLOADER,         // Bootloader status
    SUSPICIOUS_APP      // Unknown app with dangerous perms
}

/**
 * Sovereignty Domains - Binary assessment of each privacy domain.
 * You are either SOVEREIGN or COMPROMISED in each domain.
 */
enum class SovereigntyDomain {
    LOCATION,           // Can you move without being tracked?
    AUDIO,              // Can you speak privately?
    VISUAL,             // Can you exist without being seen?
    COMMUNICATIONS,     // Can you message/call privately?
    IDENTITY,           // Can you remain anonymous?
    NETWORK,            // Can you connect privately?
    DEVICE_CONTROL;     // Do you control your device?

    fun displayName(): String = when (this) {
        LOCATION -> "Location"
        AUDIO -> "Audio"
        VISUAL -> "Visual"
        COMMUNICATIONS -> "Communications"
        IDENTITY -> "Identity"
        NETWORK -> "Network"
        DEVICE_CONTROL -> "Device Control"
    }

    fun description(): String = when (this) {
        LOCATION -> "Can you move without being tracked?"
        AUDIO -> "Can you speak privately?"
        VISUAL -> "Can you exist without being seen?"
        COMMUNICATIONS -> "Can you message/call privately?"
        IDENTITY -> "Can you remain anonymous?"
        NETWORK -> "Can you connect privately?"
        DEVICE_CONTROL -> "Do you control your device?"
    }
}

/**
 * Privacy Entities - Organizations that may have access to your data.
 * Used for cumulative privacy exposure scoring.
 */
enum class PrivacyEntity {
    GOOGLE,
    SAMSUNG,
    QUALCOMM,
    META,               // Facebook/Instagram/WhatsApp
    AMAZON,
    MICROSOFT,
    CARRIER,            // Verizon, AT&T, T-Mobile, etc.
    CHINESE_TECH,       // Baidu, Tencent, Alibaba, JiGuang, Xiaomi, Huawei
    THIRD_PARTY_TRACKER; // AppsFlyer, Adjust, Branch, etc.

    fun displayName(): String = when (this) {
        GOOGLE -> "Google"
        SAMSUNG -> "Samsung"
        QUALCOMM -> "Qualcomm"
        META -> "Meta"
        AMAZON -> "Amazon"
        MICROSOFT -> "Microsoft"
        CARRIER -> "Carrier"
        CHINESE_TECH -> "Chinese Tech"
        THIRD_PARTY_TRACKER -> "Third-Party Trackers"
    }
}

/**
 * Status of a sovereignty domain - either sovereign or compromised.
 */
data class DomainStatus(
    val domain: SovereigntyDomain,
    val isSovereign: Boolean,
    val compromisedBy: List<String> = emptyList() // Package names that compromise this domain
)

/**
 * Privacy exposure to a specific entity.
 */
data class EntityExposure(
    val entity: PrivacyEntity,
    val packages: List<String>,  // Packages sending data to this entity
    val dataTypes: Set<String>   // Types of data: "location", "contacts", "usage", etc.
)
