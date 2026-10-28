package com.mekari.mobile_hardening_kit

import android.content.Context
import android.content.pm.PackageInfo
import android.os.Build
import android.os.Debug
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.util.ReflectionHelpers

/** Robolectric's Debug has no controllable debugger state. */
@Implements(Debug::class)
class DebugShadow {
  companion object {
    var connected = false
    var waiting = false

    @Implementation
    @JvmStatic
    fun isDebuggerConnected() = connected

    @Implementation
    @JvmStatic
    fun waitingForDebugger() = waiting
  }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], shadows = [DebugShadow::class])
class IntegrityDetectorsTest {
  private lateinit var context: Context
  private val originalTags = ReflectionHelpers.getStaticField<Any?>(Build::class.java, "TAGS")

  @Before
  fun setUp() {
    context = RuntimeEnvironment.getApplication()
    ReflectionHelpers.setStaticField(Build::class.java, "TAGS", "release-keys")
    DebugShadow.connected = false
    DebugShadow.waiting = false
  }

  @After
  fun tearDown() {
    ReflectionHelpers.setStaticField(Build::class.java, "TAGS", originalTags)
  }

  private fun files(maps: List<String>? = null, threads: Map<String, String>? = null) = FakeFiles().apply {
    maps?.let { contents["/proc/self/maps"] = it }
    threads?.let { named ->
      dirs["/proc/self/task"] = named.keys.toList()
      named.forEach { (tid, name) -> contents["/proc/self/task/$tid/comm"] = listOf(name) }
    }
  }

  private fun instrumentation(files: FileAccess): HardeningSignal? =
    MobileHardeningKit(context, files).snapshot().singleOrNull { it.type == HardeningSignalType.INSTRUMENTATION }

  private fun map(perms: String, path: String = "") = "7f00-7f01 $perms 00000000 00:01 0 $path".trimEnd()

  // --- threadName -------------------------------------------------------------------------------

  @Test
  fun fridaThreadsAreAPrimaryHitAndListGlibThreadsAsArtifacts() {
    val threads = mapOf("1" to "main", "2" to "gum-js-loop", "3" to "gmain", "4" to "gdbus", "5" to "pool-frida")
    val signal = instrumentation(files(threads = threads))!!
    assertEquals(
      listOf("thread:gum-js-loop", "thread:pool-frida", "thread:gmain", "thread:gdbus").sorted(),
      (signal.metadata["artifacts"] as List<*>).sortedBy { it.toString() }
    )
    assertEquals(listOf("threadName"), signal.metadata["techniques"])
    assertEquals(0, signal.metadata["tracerPort"])
    assertEquals(0, signal.metadata["anonRwxCount"])
    assertEquals(0, signal.metadata["artTextSegments"])
  }

  @Test
  fun poolFridaAloneIsPrimary() {
    val signal = instrumentation(files(threads = mapOf("1" to "pool-frida\n")))!!
    assertEquals(listOf("thread:pool-frida"), signal.metadata["artifacts"])
  }

  @Test
  fun glibThreadsAloneAreNotReported() {
    assertNull(instrumentation(files(threads = mapOf("1" to "gmain", "2" to "gdbus", "3" to "RenderThread"))))
  }

  @Test
  fun unreadableThreadEntriesAreSkipped() {
    val fake = files(threads = mapOf("1" to "gum-js-loop"))
    fake.dirs["/proc/self/task"] = listOf("1", "2", "3")
    fake.contents["/proc/self/task/3/comm"] = emptyList()
    assertEquals(listOf("thread:gum-js-loop"), instrumentation(fake)!!.metadata["artifacts"])
  }

  @Test
  fun missingTaskDirectoryIsIgnored() {
    assertNull(instrumentation(FakeFiles()))
  }

  // --- maps terms -------------------------------------------------------------------------------

  @Test
  fun gumJsLoopAndBareGadgetNoLongerMatchMaps() {
    val maps = listOf(map("r-xp", "/data/app/gum-js-loop.so"), map("r-xp", "/system/lib64/libgadget.so"))
    assertNull(instrumentation(files(maps)))
  }

  @Test
  fun fridaGadgetAndHookerNamesMatchMaps() {
    val maps = listOf(
      map("r-xp", "/data/app/libfrida-gadget.so"), map("r--p", "/data/app/libsubstrate.so"),
      map("r--p", "/data/app/libhooker.so"), map("r--p", "/data/app/XPOSED.jar"), map("r--p", "/system/lib/libc.so")
    )
    val signal = instrumentation(files(maps))!!
    assertEquals(
      listOf("/data/app/libfrida-gadget.so", "/data/app/libsubstrate.so", "/data/app/libhooker.so", "/data/app/XPOSED.jar"),
      signal.metadata["artifacts"]
    )
    assertEquals(listOf("maps"), signal.metadata["techniques"])
  }

  @Test
  fun artifactsAreBoundedInCountAndLength() {
    val maps = (1..10).map { map("r--p", "/data/frida-$it.so") } + map("r--p", "/data/frida-" + "x".repeat(200))
    val artifacts = instrumentation(files(maps))!!.metadata["artifacts"] as List<*>
    assertEquals(8, artifacts.size)
    val long = instrumentation(files(listOf(map("r--p", "/data/frida-" + "x".repeat(200)))))!!
    assertEquals(120, (long.metadata["artifacts"] as List<*>).single().toString().length)
  }

  @Test
  fun malformedMapsRowsAreIgnored() {
    assertNull(instrumentation(files(listOf("", "garbage", map("r--p", "/system/lib64/libc.so")))))
  }

  // --- memfdExec / anonRwx / artSegments --------------------------------------------------------

  @Test
  fun cleanBaselineJitCacheMemfdIsNotAHit() {
    val maps = listOf(
      map("r--s", "/memfd:jit-cache (deleted)"), map("r-xs", "/memfd:jit-cache (deleted)"),
      map("rw-s", "/memfd:jit-cache (deleted)"), map("r-xp", "[anon:dart-code]"), map("r-xp", "[vdso]")
    )
    assertNull(instrumentation(files(maps)))
  }

  @Test
  fun privateExecutableJitCacheMemfdIsNotAHit() {
    assertNull(instrumentation(files(listOf(map("r-xp", "/memfd:jit-cache (deleted)")))))
  }

  @Test
  fun privateExecutableFridaAgentMemfdIsAHit() {
    val signal = instrumentation(files(listOf(map("r-xp", "/memfd:frida-agent-64.so (deleted)"))))!!
    assertEquals(listOf("/memfd:frida-agent-64.so"), signal.metadata["artifacts"])
    assertEquals(listOf("maps", "memfdExec"), signal.metadata["techniques"])
  }

  @Test
  fun memfdExecWorksForUnknownNamesAndNeedsExecPermission() {
    val signal = instrumentation(files(listOf(map("r-xp", "/memfd:payload"), map("rw-p", "/memfd:data"))))!!
    assertEquals(listOf("/memfd:payload"), signal.metadata["artifacts"])
    assertEquals(listOf("memfdExec"), signal.metadata["techniques"])
  }

  @Test
  fun anonymousRwxAloneNeverTriggers() {
    assertNull(instrumentation(files(listOf(map("rwxp"), map("rwxp"), map("rwxp", "[anon:v8]")))))
  }

  @Test
  fun anonymousRwxIsSupportingEvidenceAlongsideAPrimaryHit() {
    val maps = listOf(map("rwxp"), map("rwxp"), map("rwxp"), map("r--p", "/data/frida-agent.so"))
    val signal = instrumentation(files(maps))!!
    assertEquals(3, signal.metadata["anonRwxCount"])
    assertEquals(listOf("maps", "anonRwx"), signal.metadata["techniques"])
  }

  @Test
  fun libartSingleSegmentIsCleanAndManyAreAHit() {
    val one = listOf(map("r-xp", "/apex/com.android.art/lib64/libart.so"), map("r--p", "/apex/x/lib64/libart.so"))
    assertNull(instrumentation(files(one)))
    val many = (1..15).map { map("r-xp", "/apex/com.android.art/lib64/libart.so") }
    val signal = instrumentation(files(many))!!
    assertEquals(15, signal.metadata["artTextSegments"])
    assertEquals(listOf("artSegments"), signal.metadata["techniques"])
    assertEquals(emptyList<String>(), signal.metadata["artifacts"])
  }

  // --- port probe -------------------------------------------------------------------------------

  private val fridaPortTcp = listOf(
    "  sl  local_address rem_address   st",
    "   0: 0100007F:69A2 00000000:0000 0A 00000000:00000000"
  )

  @Test
  @Config(sdk = [28])
  fun portProbeRunsOnApi28() {
    val fake = FakeFiles(contents = mapOf("/proc/net/tcp" to fridaPortTcp))
    val signal = instrumentation(fake)!!
    assertEquals(27042, signal.metadata["tracerPort"])
    assertEquals(listOf("port"), signal.metadata["techniques"])
  }

  @Test
  @Config(sdk = [29])
  fun portProbeIsSkippedFromApi29() {
    assertNull(instrumentation(FakeFiles(contents = mapOf("/proc/net/tcp" to fridaPortTcp))))
    val withHit = instrumentation(
      files(listOf(map("r--p", "/data/frida.so"))).apply { contents["/proc/net/tcp"] = fridaPortTcp }
    )!!
    assertEquals(0, withHit.metadata["tracerPort"])
    assertFalse("port" in (withHit.metadata["techniques"] as List<*>))
  }

  // --- debuggerAttach ---------------------------------------------------------------------------

  private fun debugger(files: FileAccess): HardeningSignal? =
    MobileHardeningKit(context, files).snapshot().singleOrNull { it.type == HardeningSignalType.DEBUGGER_ATTACH }

  private fun status(tracer: String) = FakeFiles(contents = mapOf("/proc/self/status" to listOf("Name:\tapp", "TracerPid:\t$tracer")))

  @Test
  fun nonZeroTracerPidIsReported() {
    val signal = debugger(status("4242"))!!
    assertEquals(
      mapOf("debuggerConnected" to false, "tracerPid" to true, "techniques" to listOf("tracerPid")),
      signal.metadata
    )
  }

  @Test
  fun zeroOrUnreadableTracerPidIsClean() {
    assertNull(debugger(status("0")))
    assertNull(debugger(FakeFiles()))
    assertNull(debugger(FakeFiles(contents = mapOf("/proc/self/status" to listOf("Name:\tapp")))))
    assertNull(debugger(status("garbage")))
  }

  @Test
  fun jdwpConnectedAndWaitingAreReported() {
    DebugShadow.connected = true
    assertEquals(
      mapOf("debuggerConnected" to true, "tracerPid" to false, "techniques" to listOf("jdwp")),
      debugger(FakeFiles())!!.metadata
    )
    DebugShadow.connected = false
    DebugShadow.waiting = true
    assertEquals(false, debugger(FakeFiles())!!.metadata["debuggerConnected"])
    DebugShadow.connected = true
    assertEquals(listOf("jdwp", "tracerPid"), debugger(status("7"))!!.metadata["techniques"])
  }

  // --- root: mountinfo --------------------------------------------------------------------------

  private fun mountinfo(vararg rows: String) = FakeFiles(contents = mapOf("/proc/self/mountinfo" to rows.toList()))

  private fun root(files: FileAccess): HardeningSignal? =
    MobileHardeningKit(context, files).snapshot().singleOrNull { it.type == HardeningSignalType.ROOT }

  @Test
  fun mountinfoMarkersAreMatchedCaseInsensitivelyOnSourceAndPathFields() {
    val signal = root(
      mountinfo(
        "100 90 0:25 / /system rw,relatime shared:1 - ext4 /dev/block/dm-0 ro",
        "101 90 0:26 / /system/bin rw - tmpfs Magisk rw",
        "102 90 0:27 /adb/modules/lsp/system /system/lib64 ro - ext4 /dev/block/dm-1 rw",
        "103 90 0:28 / /data/adb/zygisk-stuff ro - tmpfs tmpfs rw",
        "104 90 0:29 / /mnt rw,magisk=1 - ext4 /dev/block/dm-2 rw",
        "short"
      )
    )!!
    assertEquals(listOf("magisk", "zygisk", "/adb/modules"), signal.metadata["mountMarkers"])
    assertEquals(listOf("mountinfo"), signal.metadata["techniques"])
  }

  @Test
  fun mountOptionsAloneAreNotMatchedAndUnreadableMountinfoIsClean() {
    assertNull(root(mountinfo("104 90 0:29 / /mnt rw,magisk=1 shared:magisk - ext4 /dev/block/dm-2 rw")))
    assertNull(root(FakeFiles()))
  }

  @Test
  fun rootTechniquesCombineAllSources() {
    ReflectionHelpers.setStaticField(Build::class.java, "TAGS", "test-keys")
    shadowOf(context.packageManager).installPackage(PackageInfo().apply { packageName = "com.topjohnwu.magisk" })
    val fake = FakeFiles(
      existing = setOf("/sbin/su"),
      contents = mapOf("/proc/self/mountinfo" to listOf("1 0 0:1 / /x rw - tmpfs zygisk rw"))
    )
    val signal = root(fake)!!
    assertEquals(listOf("paths", "buildTags", "managerPackage", "mountinfo"), signal.metadata["techniques"])
    assertEquals(listOf("zygisk"), signal.metadata["mountMarkers"])
    assertEquals(listOf("/sbin/su"), signal.metadata["artifacts"])
  }

  @Test
  fun rootFromTestKeysOnlyHasNoMountMarkers() {
    ReflectionHelpers.setStaticField(Build::class.java, "TAGS", "test-keys")
    val signal = root(FakeFiles())!!
    assertEquals(mapOf("testKeys" to true, "techniques" to listOf("buildTags")), signal.metadata)
  }

  // --- tiers ------------------------------------------------------------------------------------

  @Test
  fun runtimeTierCoversOnlyInstrumentationAndDebugger() {
    ReflectionHelpers.setStaticField(Build::class.java, "TAGS", "test-keys")
    val fake = files(listOf(map("r--p", "/data/frida.so"))).apply {
      contents["/proc/self/status"] = listOf("TracerPid:\t5")
    }
    val kit = MobileHardeningKit(context, fake)
    assertEquals(
      listOf(HardeningSignalType.INSTRUMENTATION, HardeningSignalType.DEBUGGER_ATTACH),
      kit.runtimeSignals().map { it.type }
    )
    assertEquals(
      listOf(HardeningSignalType.ROOT, HardeningSignalType.INSTRUMENTATION, HardeningSignalType.DEBUGGER_ATTACH),
      kit.snapshot().map { it.type }
    )
  }

  @Test
  fun systemFilesListDirectories() {
    val dir = java.io.File.createTempFile("hardening", "dir").apply {
      delete()
      mkdir()
      deleteOnExit()
    }
    java.io.File(dir, "a").apply { createNewFile(); deleteOnExit() }
    assertEquals(listOf("a"), SystemFiles.list(dir.path))
    assertTrue(SystemFiles.list(dir.path + "/missing").isEmpty())
  }
}
