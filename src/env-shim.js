// Must be imported first, before anything that might call os.homedir()
// (the AWS SDK does this internally during client setup, even when
// credentials are passed explicitly - it still probes for ~/.aws/config).
// Wasmer's sandbox has no normal user/home-directory entry, so that lookup
// throws "uv_os_homedir returned ENOENT". Node's os.homedir() reads
// process.env.HOME first before ever hitting the OS - setting it here
// short-circuits the failing lookup entirely.
process.env.HOME = process.env.HOME || "/tmp";
