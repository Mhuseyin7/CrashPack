# Exit codes

CrashPack uses `0` for success and a non-zero code for a failed operation. Scripts should treat any non-zero code as a bundle that must not be shared. Errors always explain whether configuration, collection, redaction, archive inspection, or checksum verification failed. A future major release may reserve distinct numeric codes; callers should not depend on a particular non-zero value yet.
