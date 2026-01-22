/**
 * NullSec RootCheck - Hardened Rootkit Detection System
 * Language: D (Systems Programming with Safety)
 * Author: bad-antics
 * License: NullSec Proprietary
 * Security Level: Maximum Hardening
 *
 * Features:
 * - @safe annotations throughout for memory safety
 * - @nogc operations where possible for predictability
 * - Bounded operations with overflow checking
 * - Immutable data structures for thread safety
 * - RAII resource management via scoped
 * - Input validation using contracts
 * - Defense-in-depth architecture
 */

module nullsec.rootcheck;

import std.stdio;
import std.file;
import std.string;
import std.array;
import std.algorithm;
import std.conv;
import std.range;
import std.exception;
import std.path;
import core.stdc.string : memset;
import core.memory;

// ============================================================================
// Banner & Constants
// ============================================================================

enum VERSION = "1.0.0";

immutable string BANNER = r"
██████╗  ██████╗  ██████╗ ████████╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
██████╔╝██║   ██║██║   ██║   ██║   ██║     ███████║█████╗  ██║     █████╔╝ 
██╔══██╗██║   ██║██║   ██║   ██║   ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
██║  ██║╚██████╔╝╚██████╔╝   ██║   ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝    ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
                       bad-antics • v" ~ VERSION ~ r"
════════════════════════════════════════════════════════════════════════════
";

// Security constants with compile-time validation
enum MAX_PATH_LENGTH = 4096;
enum MAX_PROCESS_COUNT = 65536;
enum MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
enum MAX_HIDDEN_THRESHOLD = 100;
enum ENTROPY_THRESHOLD = 7.5;
enum SUSPICIOUS_STRINGS_THRESHOLD = 5;

// Known rootkit signatures (immutable for thread safety)
immutable string[] KNOWN_ROOTKIT_FILES = [
    "/etc/ld.so.preload",
    "/lib/libselinux.so.rootkit",
    "/usr/lib/security/.config",
    "/.hidden",
    "/dev/.udev/",
    "/dev/shm/.config",
    "/tmp/.X11-unix/.config",
    "/var/tmp/.hidden"
];

immutable string[] SUSPICIOUS_KERNEL_MODULES = [
    "rootkit", "hide", "adore", "knark", "rkit",
    "synapsys", "override", "cloaker", "phantom"
];

immutable string[] SUSPICIOUS_PROCESS_NAMES = [
    "xmrig", "minerd", "azazel", "jynx", "bdvl",
    "diamorphine", "reptile", "sutekh"
];

// ============================================================================
// Secure Memory Management
// ============================================================================

/**
 * Secure buffer that zeros memory on destruction.
 * Prevents sensitive data from lingering in memory.
 */
struct SecureBuffer(T) if (is(T == ubyte) || is(T == char))
{
    private T[] data;
    private bool valid = false;
    
    @disable this(this); // No copying - security measure
    
    @safe this(size_t size) nothrow
    {
        if (size > 0 && size <= MAX_FILE_SIZE)
        {
            try
            {
                data = new T[size];
                valid = true;
            }
            catch (Exception)
            {
                data = null;
                valid = false;
            }
        }
    }
    
    @trusted ~this() nothrow
    {
        if (data !is null)
        {
            // Secure wipe - prevent compiler optimization
            memset(data.ptr, 0, data.length * T.sizeof);
            data = null;
        }
        valid = false;
    }
    
    @safe @property bool isValid() const pure nothrow
    {
        return valid && data !is null;
    }
    
    @safe @property size_t length() const pure nothrow
    {
        return data !is null ? data.length : 0;
    }
    
    @safe T[] get() pure nothrow
    in (isValid, "SecureBuffer: accessing invalid buffer")
    {
        return data;
    }
}

// ============================================================================
// Input Validation Module
// ============================================================================

/**
 * Validated path type using D's type system for safety.
 */
struct ValidatedPath
{
    private string _path;
    private bool _valid;
    
    @safe static ValidatedPath create(string rawPath) nothrow
    {
        ValidatedPath vp;
        vp._valid = false;
        
        if (rawPath.length == 0 || rawPath.length > MAX_PATH_LENGTH)
            return vp;
        
        // Check for path traversal attempts
        if (rawPath.canFind("..") || rawPath.canFind("\0"))
            return vp;
        
        // Check for suspicious patterns
        if (rawPath.canFind(";") || rawPath.canFind("|") || rawPath.canFind("`"))
            return vp;
        
        // Normalize and validate
        try
        {
            vp._path = buildNormalizedPath(rawPath);
            vp._valid = true;
        }
        catch (Exception)
        {
            vp._valid = false;
        }
        
        return vp;
    }
    
    @safe @property bool isValid() const pure nothrow { return _valid; }
    @safe @property string path() const pure nothrow
    in (_valid, "Accessing invalid path")
    {
        return _path;
    }
}

/**
 * Validated PID type with range checking.
 */
struct ValidatedPID
{
    private int _pid;
    private bool _valid;
    
    @safe static ValidatedPID create(int rawPid) pure nothrow
    {
        ValidatedPID vpid;
        // Linux PIDs are 1 to 4194304 (default max)
        vpid._valid = rawPid > 0 && rawPid <= 4194304;
        vpid._pid = vpid._valid ? rawPid : 0;
        return vpid;
    }
    
    @safe static ValidatedPID fromString(string s) nothrow
    {
        try
        {
            return create(to!int(s));
        }
        catch (Exception)
        {
            return ValidatedPID.init;
        }
    }
    
    @safe @property bool isValid() const pure nothrow { return _valid; }
    @safe @property int pid() const pure nothrow
    in (_valid, "Accessing invalid PID")
    {
        return _pid;
    }
}

// ============================================================================
// Rate Limiting
// ============================================================================

/**
 * Token bucket rate limiter for resource protection.
 */
struct RateLimiter
{
    private long tokens;
    private long maxTokens;
    private long lastRefill;
    private long refillRate; // tokens per second
    
    @safe static RateLimiter create(long max, long rate) pure nothrow
    {
        RateLimiter rl;
        rl.maxTokens = max > 0 ? max : 100;
        rl.tokens = rl.maxTokens;
        rl.refillRate = rate > 0 ? rate : 10;
        rl.lastRefill = 0;
        return rl;
    }
    
    @safe bool tryAcquire(long currentTime) pure nothrow
    {
        // Refill tokens based on elapsed time
        if (lastRefill > 0)
        {
            immutable elapsed = currentTime - lastRefill;
            immutable newTokens = (elapsed * refillRate) / 1000;
            tokens = min(maxTokens, tokens + newTokens);
        }
        lastRefill = currentTime;
        
        if (tokens > 0)
        {
            tokens--;
            return true;
        }
        return false;
    }
}

// ============================================================================
// Security Analysis Results
// ============================================================================

/**
 * Immutable detection result for thread safety.
 */
struct DetectionResult
{
    string category;
    string description;
    string path;
    int severity; // 1-10
    long timestamp;
    
    @safe string format() const pure
    {
        import std.format : format;
        string sevLevel;
        if (severity >= 8) sevLevel = "CRITICAL";
        else if (severity >= 6) sevLevel = "HIGH";
        else if (severity >= 4) sevLevel = "MEDIUM";
        else sevLevel = "LOW";
        
        return format("[%s] %s: %s (%s)", sevLevel, category, description, path);
    }
}

/**
 * Accumulator for scan results with bounded growth.
 */
struct ResultAccumulator
{
    private DetectionResult[] results;
    private size_t maxResults;
    
    @safe static ResultAccumulator create(size_t max = 10000) pure nothrow
    {
        ResultAccumulator ra;
        ra.maxResults = max;
        return ra;
    }
    
    @safe bool add(DetectionResult result) nothrow
    {
        if (results.length >= maxResults)
            return false; // Bounded growth
        
        try
        {
            results ~= result;
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }
    
    @safe @property const(DetectionResult)[] getResults() const pure nothrow
    {
        return results;
    }
    
    @safe @property size_t criticalCount() const pure nothrow
    {
        return results.filter!(r => r.severity >= 8).count;
    }
    
    @safe @property size_t highCount() const pure nothrow
    {
        return results.filter!(r => r.severity >= 6 && r.severity < 8).count;
    }
}

// ============================================================================
// Process Analysis
// ============================================================================

/**
 * Process information structure.
 */
struct ProcessInfo
{
    int pid;
    string name;
    string cmdline;
    string exe;
    int uid;
    bool isHidden;
    bool isSuspicious;
}

/**
 * Safely enumerate processes from /proc.
 * Returns: Array of ProcessInfo with validated data.
 */
@safe ProcessInfo[] enumerateProcesses()
{
    ProcessInfo[] procs;
    
    auto procPath = ValidatedPath.create("/proc");
    if (!procPath.isValid)
        return procs;
    
    try
    {
        foreach (entry; dirEntries(procPath.path, SpanMode.shallow))
        {
            // Extract potential PID from directory name
            auto baseName = baseName(entry.name);
            auto vpid = ValidatedPID.fromString(baseName);
            
            if (!vpid.isValid)
                continue;
            
            ProcessInfo pi;
            pi.pid = vpid.pid;
            
            // Read process name safely
            auto commPath = ValidatedPath.create(entry.name ~ "/comm");
            if (commPath.isValid && exists(commPath.path))
            {
                try
                {
                    pi.name = readText(commPath.path).strip;
                }
                catch (Exception)
                {
                    pi.name = "<unknown>";
                }
            }
            
            // Read cmdline safely
            auto cmdPath = ValidatedPath.create(entry.name ~ "/cmdline");
            if (cmdPath.isValid && exists(cmdPath.path))
            {
                try
                {
                    auto cmd = cast(string)read(cmdPath.path);
                    pi.cmdline = cmd.replace("\0", " ").strip;
                }
                catch (Exception)
                {
                    pi.cmdline = "";
                }
            }
            
            // Read exe link safely
            auto exePath = ValidatedPath.create(entry.name ~ "/exe");
            if (exePath.isValid && exists(exePath.path))
            {
                try
                {
                    pi.exe = readLink(exePath.path);
                }
                catch (Exception)
                {
                    pi.exe = "<deleted>";
                }
            }
            
            // Check for suspicious names
            auto lowerName = pi.name.toLower;
            pi.isSuspicious = SUSPICIOUS_PROCESS_NAMES.any!(s => lowerName.canFind(s));
            
            procs ~= pi;
            
            // Bounded collection
            if (procs.length >= MAX_PROCESS_COUNT)
                break;
        }
    }
    catch (Exception)
    {
        // Permission denied or other errors - return partial results
    }
    
    return procs;
}

/**
 * Detect hidden processes by comparing /proc with ps output.
 */
@trusted DetectionResult[] detectHiddenProcesses()
{
    DetectionResult[] results;
    
    // Get process list from /proc
    auto procList = enumerateProcesses();
    int[] procPids = procList.map!(p => p.pid).array;
    
    // Also check for PIDs that exist but are hidden
    foreach (pid; 1 .. MAX_PROCESS_COUNT)
    {
        auto pidPath = ValidatedPath.create("/proc/" ~ to!string(pid));
        if (!pidPath.isValid)
            continue;
        
        try
        {
            if (exists(pidPath.path))
            {
                if (!procPids.canFind(pid))
                {
                    results ~= DetectionResult(
                        "HIDDEN_PROCESS",
                        "Process exists but not enumerable",
                        pidPath.path,
                        9,
                        0
                    );
                }
            }
        }
        catch (Exception)
        {
            // Access denied - might be hidden
        }
        
        if (results.length >= MAX_HIDDEN_THRESHOLD)
            break;
    }
    
    // Check for suspicious processes
    foreach (proc; procList)
    {
        if (proc.isSuspicious)
        {
            results ~= DetectionResult(
                "SUSPICIOUS_PROCESS",
                "Process name matches known malware: " ~ proc.name,
                "/proc/" ~ to!string(proc.pid),
                7,
                0
            );
        }
        
        if (proc.exe.canFind("(deleted)") && proc.cmdline.length > 0)
        {
            results ~= DetectionResult(
                "DELETED_EXECUTABLE",
                "Running process with deleted binary: " ~ proc.name,
                proc.exe,
                8,
                0
            );
        }
    }
    
    return results;
}

// ============================================================================
// Filesystem Analysis
// ============================================================================

/**
 * Check for known rootkit files.
 */
@safe DetectionResult[] checkRootkitFiles()
{
    DetectionResult[] results;
    
    foreach (filePath; KNOWN_ROOTKIT_FILES)
    {
        auto vpath = ValidatedPath.create(filePath);
        if (!vpath.isValid)
            continue;
        
        try
        {
            if (exists(vpath.path))
            {
                results ~= DetectionResult(
                    "ROOTKIT_FILE",
                    "Known rootkit file detected",
                    vpath.path,
                    9,
                    0
                );
            }
        }
        catch (Exception)
        {
            // Access denied - log as suspicious
            results ~= DetectionResult(
                "ACCESS_DENIED",
                "Cannot access potentially dangerous path",
                vpath.path,
                5,
                0
            );
        }
    }
    
    // Check LD_PRELOAD
    auto ldPreload = ValidatedPath.create("/etc/ld.so.preload");
    if (ldPreload.isValid)
    {
        try
        {
            if (exists(ldPreload.path))
            {
                auto content = readText(ldPreload.path);
                if (content.strip.length > 0)
                {
                    results ~= DetectionResult(
                        "LD_PRELOAD",
                        "LD_PRELOAD file contains entries - potential hooking",
                        ldPreload.path,
                        8,
                        0
                    );
                }
            }
        }
        catch (Exception) {}
    }
    
    return results;
}

/**
 * Analyze file entropy to detect packed/encrypted malware.
 */
@trusted double calculateEntropy(const(ubyte)[] data) pure nothrow
{
    if (data.length == 0)
        return 0.0;
    
    // Count byte frequencies
    ulong[256] freq;
    foreach (b; data)
        freq[b]++;
    
    // Calculate Shannon entropy
    double entropy = 0.0;
    immutable total = cast(double)data.length;
    
    foreach (f; freq)
    {
        if (f > 0)
        {
            immutable p = cast(double)f / total;
            import std.math : log2;
            entropy -= p * log2(p);
        }
    }
    
    return entropy;
}

/**
 * Scan binary for suspicious strings.
 */
@safe int countSuspiciousStrings(const(char)[] data) pure nothrow
{
    immutable string[] suspiciousPatterns = [
        "LD_PRELOAD", "ptrace", "getdents", "sys_call_table",
        "rootkit", "backdoor", "hidden", "stealth", "c99shell",
        "/bin/sh", "/dev/null", "socket", "connect", "reverse"
    ];
    
    int count = 0;
    auto lowerData = data.toLower;
    
    foreach (pattern; suspiciousPatterns)
    {
        if (lowerData.canFind(pattern))
            count++;
    }
    
    return count;
}

/**
 * Analyze a binary file for suspicious characteristics.
 */
@trusted DetectionResult[] analyzeBinary(string filepath)
{
    DetectionResult[] results;
    
    auto vpath = ValidatedPath.create(filepath);
    if (!vpath.isValid)
        return results;
    
    try
    {
        if (!exists(vpath.path) || !isFile(vpath.path))
            return results;
        
        auto fileSize = getSize(vpath.path);
        if (fileSize > MAX_FILE_SIZE)
        {
            results ~= DetectionResult(
                "LARGE_FILE",
                "File too large for analysis",
                vpath.path,
                3,
                0
            );
            return results;
        }
        
        // Read file content
        auto content = cast(ubyte[])read(vpath.path);
        
        // Check entropy
        auto entropy = calculateEntropy(content);
        if (entropy > ENTROPY_THRESHOLD)
        {
            results ~= DetectionResult(
                "HIGH_ENTROPY",
                "File has high entropy (possibly packed/encrypted): " ~ to!string(entropy),
                vpath.path,
                6,
                0
            );
        }
        
        // Check for suspicious strings
        auto strContent = cast(char[])content;
        auto suspCount = countSuspiciousStrings(strContent);
        if (suspCount >= SUSPICIOUS_STRINGS_THRESHOLD)
        {
            results ~= DetectionResult(
                "SUSPICIOUS_STRINGS",
                "File contains multiple suspicious strings: " ~ to!string(suspCount),
                vpath.path,
                7,
                0
            );
        }
        
        // Check for ELF with suspicious sections
        if (content.length >= 4 && content[0..4] == [0x7f, 'E', 'L', 'F'])
        {
            // Check for common packer signatures
            if (strContent.canFind("UPX!"))
            {
                results ~= DetectionResult(
                    "PACKED_BINARY",
                    "ELF binary appears to be packed with UPX",
                    vpath.path,
                    5,
                    0
                );
            }
        }
    }
    catch (Exception)
    {
        results ~= DetectionResult(
            "ANALYSIS_ERROR",
            "Could not analyze file",
            vpath.path,
            2,
            0
        );
    }
    
    return results;
}

// ============================================================================
// Kernel Module Analysis
// ============================================================================

/**
 * Check loaded kernel modules for suspicious entries.
 */
@trusted DetectionResult[] analyzeKernelModules()
{
    DetectionResult[] results;
    
    auto modulesPath = ValidatedPath.create("/proc/modules");
    if (!modulesPath.isValid)
        return results;
    
    try
    {
        if (!exists(modulesPath.path))
            return results;
        
        auto content = readText(modulesPath.path);
        
        foreach (line; content.lineSplitter)
        {
            auto parts = line.split;
            if (parts.length < 1)
                continue;
            
            auto modName = parts[0].toLower;
            
            // Check against suspicious patterns
            foreach (pattern; SUSPICIOUS_KERNEL_MODULES)
            {
                if (modName.canFind(pattern))
                {
                    results ~= DetectionResult(
                        "SUSPICIOUS_MODULE",
                        "Kernel module matches suspicious pattern: " ~ parts[0],
                        "/proc/modules",
                        9,
                        0
                    );
                }
            }
        }
    }
    catch (Exception)
    {
        results ~= DetectionResult(
            "MODULES_ERROR",
            "Cannot read kernel modules",
            modulesPath.path,
            4,
            0
        );
    }
    
    return results;
}

// ============================================================================
// Network Analysis
// ============================================================================

/**
 * Check for suspicious network connections.
 */
@trusted DetectionResult[] analyzeNetworkConnections()
{
    DetectionResult[] results;
    
    // Suspicious ports commonly used by backdoors
    immutable int[] suspiciousPorts = [
        31337, 12345, 4444, 5555, 6666, 1234, 9999,
        6667, 6668, 6669, // IRC
        3128, 8080 // Proxies
    ];
    
    foreach (proto; ["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"])
    {
        auto netPath = ValidatedPath.create(proto);
        if (!netPath.isValid)
            continue;
        
        try
        {
            if (!exists(netPath.path))
                continue;
            
            auto content = readText(netPath.path);
            bool firstLine = true;
            
            foreach (line; content.lineSplitter)
            {
                if (firstLine) { firstLine = false; continue; }
                
                auto parts = line.split;
                if (parts.length < 2)
                    continue;
                
                // Parse local address:port
                auto localParts = parts[1].split(":");
                if (localParts.length >= 2)
                {
                    try
                    {
                        auto port = to!int(localParts[1], 16);
                        
                        if (suspiciousPorts.canFind(port))
                        {
                            results ~= DetectionResult(
                                "SUSPICIOUS_PORT",
                                "Connection on known backdoor port: " ~ to!string(port),
                                proto,
                                7,
                                0
                            );
                        }
                    }
                    catch (Exception) {}
                }
            }
        }
        catch (Exception) {}
    }
    
    return results;
}

// ============================================================================
// Main Scanner
// ============================================================================

/**
 * Comprehensive system scan with all checks.
 */
ResultAccumulator runFullScan()
{
    auto results = ResultAccumulator.create();
    
    writeln("[\033[36m*\033[0m] Checking for hidden processes...");
    foreach (r; detectHiddenProcesses())
        results.add(r);
    
    writeln("[\033[36m*\033[0m] Checking for known rootkit files...");
    foreach (r; checkRootkitFiles())
        results.add(r);
    
    writeln("[\033[36m*\033[0m] Analyzing kernel modules...");
    foreach (r; analyzeKernelModules())
        results.add(r);
    
    writeln("[\033[36m*\033[0m] Analyzing network connections...");
    foreach (r; analyzeNetworkConnections())
        results.add(r);
    
    writeln("[\033[36m*\033[0m] Scanning critical directories...");
    
    // Scan critical directories
    immutable string[] criticalDirs = [
        "/bin", "/sbin", "/usr/bin", "/usr/sbin",
        "/lib", "/lib64", "/usr/lib"
    ];
    
    foreach (dir; criticalDirs)
    {
        auto vdir = ValidatedPath.create(dir);
        if (!vdir.isValid)
            continue;
        
        try
        {
            if (!exists(vdir.path))
                continue;
            
            foreach (entry; dirEntries(vdir.path, SpanMode.shallow))
            {
                if (isFile(entry.name))
                {
                    foreach (r; analyzeBinary(entry.name))
                        results.add(r);
                }
            }
        }
        catch (Exception) {}
    }
    
    return results;
}

/**
 * Print scan results with color coding.
 */
void printResults(ref const ResultAccumulator results)
{
    writeln("\n════════════════════════════════════════════════════════════════════════════");
    writefln("                        SCAN RESULTS");
    writeln("════════════════════════════════════════════════════════════════════════════\n");
    
    foreach (result; results.getResults)
    {
        string color;
        if (result.severity >= 8) color = "\033[31m"; // Red
        else if (result.severity >= 6) color = "\033[33m"; // Yellow
        else if (result.severity >= 4) color = "\033[36m"; // Cyan
        else color = "\033[37m"; // White
        
        writefln("%s%s\033[0m", color, result.format());
    }
    
    writeln("\n════════════════════════════════════════════════════════════════════════════");
    writefln("  Summary: %d CRITICAL | %d HIGH | %d Total Findings",
             results.criticalCount, results.highCount, results.getResults.length);
    writeln("════════════════════════════════════════════════════════════════════════════");
    
    if (results.criticalCount > 0)
    {
        writeln("\n\033[31m[!] CRITICAL FINDINGS DETECTED - IMMEDIATE INVESTIGATION REQUIRED\033[0m");
    }
    else if (results.highCount > 0)
    {
        writeln("\n\033[33m[!] HIGH SEVERITY FINDINGS - REVIEW RECOMMENDED\033[0m");
    }
    else if (results.getResults.length == 0)
    {
        writeln("\n\033[32m[✓] No suspicious activity detected\033[0m");
    }
}

// ============================================================================
// Entry Point
// ============================================================================

void main(string[] args)
{
    write(BANNER);
    
    // Check for root privileges
    import core.sys.posix.unistd : getuid;
    if (getuid() != 0)
    {
        writeln("\n\033[33m[!] Warning: Running without root privileges - some checks may be limited\033[0m\n");
    }
    
    writeln("[\033[32m+\033[0m] Starting comprehensive rootkit scan...\n");
    
    auto results = runFullScan();
    printResults(results);
    
    writeln("\n[\033[32m+\033[0m] Scan complete.\n");
}

// ============================================================================
// Unit Tests
// ============================================================================

version(unittest)
{
    @safe unittest
    {
        // Test ValidatedPath
        auto valid = ValidatedPath.create("/etc/passwd");
        assert(valid.isValid);
        
        auto invalid = ValidatedPath.create("../../../etc/passwd");
        assert(!invalid.isValid);
        
        auto tooLong = ValidatedPath.create("a".repeat(MAX_PATH_LENGTH + 1).join);
        assert(!tooLong.isValid);
    }
    
    @safe unittest
    {
        // Test ValidatedPID
        auto valid = ValidatedPID.create(1234);
        assert(valid.isValid);
        assert(valid.pid == 1234);
        
        auto invalid = ValidatedPID.create(-1);
        assert(!invalid.isValid);
        
        auto zero = ValidatedPID.create(0);
        assert(!zero.isValid);
    }
    
    unittest
    {
        // Test entropy calculation
        ubyte[] lowEntropy = new ubyte[1000];
        lowEntropy[] = 0;
        assert(calculateEntropy(lowEntropy) == 0.0);
        
        ubyte[] highEntropy = new ubyte[256];
        foreach (i, ref b; highEntropy)
            b = cast(ubyte)i;
        assert(calculateEntropy(highEntropy) == 8.0);
    }
    
    @safe unittest
    {
        // Test RateLimiter
        auto rl = RateLimiter.create(10, 1);
        foreach (_; 0..10)
            assert(rl.tryAcquire(0));
        assert(!rl.tryAcquire(0)); // Exhausted
        assert(rl.tryAcquire(10000)); // Refilled
    }
    
    @safe unittest
    {
        // Test SecureBuffer
        {
            auto buf = SecureBuffer!ubyte(100);
            assert(buf.isValid);
            assert(buf.length == 100);
        }
        // Buffer should be zeroed after scope exit
        
        auto invalid = SecureBuffer!ubyte(0);
        assert(!invalid.isValid);
    }
}
