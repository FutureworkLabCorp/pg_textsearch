/*
 * Copyright (c) 2025-2026 Tiger Data, Inc.
 * Licensed under the PostgreSQL License. See LICENSE for details.
 *
 * compat.h - Compiler and server-version portability helpers
 */
#pragma once

#include <postgres.h>

/*
 * Packed struct marker.  c.h defines pg_attribute_packed() only for
 * compilers that spell it as an attribute, and notes that MSVC can pack
 * a struct only by wrapping its whole definition.  TP_PACKED therefore
 * expands to nothing on MSVC, and every struct that uses it wraps its
 * definition in #pragma pack(push, 1) / #pragma pack(pop).
 */
#ifdef _MSC_VER
#define TP_PACKED
#else
#define TP_PACKED pg_attribute_packed()
#endif

/*
 * PG19 requires a hand-built TupleDesc to be finalized before it is
 * blessed or otherwise used; on a cassert build BlessTupleDesc() TRAPs
 * otherwise.  Older servers have no such call, so define it away and
 * let call sites use the PG19 API unconditionally.
 */
#if PG_VERSION_NUM < 190000
#define TupleDescFinalize(tupdesc) ((void)(tupdesc))
#endif

/*
 * post_parse_analyze_hook's JumbleState parameter became const in PG19.
 * A hook implementation has to match the typedef exactly — C does not
 * consider `const JumbleState *` and `JumbleState *` compatible
 * parameter types — so the qualifier must track the server version.
 */
#if PG_VERSION_NUM >= 190000
#define TP_JUMBLE_STATE const JumbleState
#else
#define TP_JUMBLE_STATE JumbleState
#endif

/*
 * PostgreSQL 15 and 16 support.
 *
 * Upstream targets PG17+.  The shims below map the PG16/PG17 APIs the
 * code is written against onto their older equivalents, so call sites
 * stay version-agnostic.  Each block names the release that introduced
 * the API it replaces.
 */

/* PG16: RelFileNode became RelFileLocator, and its fields were renamed. */
#if PG_VERSION_NUM < 160000
typedef Oid RelFileNumber;
#define InvalidRelFileNumber InvalidOid
#define rd_locator			 rd_node
#define spcOid				 spcNode
#define dbOid				 dbNode
#define relNumber			 relNode
#endif

/* PG16: the "escontext" argument for soft errors; NULL keeps hard errors. */
#if PG_VERSION_NUM < 160000
#define stringToQualifiedNameList(string, escontext) \
	stringToQualifiedNameList(string)
#endif

/*
 * PG16: object_ownercheck() and object_aclcheck() replaced the
 * per-catalog pg_*_ownercheck() and pg_*_aclcheck() functions.  Only the
 * catalogs this extension checks are mapped.
 */
#if PG_VERSION_NUM < 160000
#include <catalog/pg_class_d.h>
#include <catalog/pg_database_d.h>
#include <catalog/pg_namespace_d.h>
#include <catalog/pg_proc_d.h>
#include <catalog/pg_tablespace_d.h>
#include <utils/acl.h>

static inline bool
tp_object_ownercheck(Oid classid, Oid objectid, Oid roleid)
{
	switch (classid)
	{
	case RelationRelationId:
		return pg_class_ownercheck(objectid, roleid);
	case DatabaseRelationId:
		return pg_database_ownercheck(objectid, roleid);
	case NamespaceRelationId:
		return pg_namespace_ownercheck(objectid, roleid);
	case ProcedureRelationId:
		return pg_proc_ownercheck(objectid, roleid);
	case TableSpaceRelationId:
		return pg_tablespace_ownercheck(objectid, roleid);
	default:
		elog(ERROR, "unsupported catalog %u for an ownership check", classid);
	}
	pg_unreachable();
}

static inline AclResult
tp_object_aclcheck(Oid classid, Oid objectid, Oid roleid, AclMode mode)
{
	switch (classid)
	{
	case RelationRelationId:
		return pg_class_aclcheck(objectid, roleid, mode);
	case DatabaseRelationId:
		return pg_database_aclcheck(objectid, roleid, mode);
	case NamespaceRelationId:
		return pg_namespace_aclcheck(objectid, roleid, mode);
	case ProcedureRelationId:
		return pg_proc_aclcheck(objectid, roleid, mode);
	case TableSpaceRelationId:
		return pg_tablespace_aclcheck(objectid, roleid, mode);
	default:
		elog(ERROR, "unsupported catalog %u for a privilege check", classid);
	}
	pg_unreachable();
}

#define object_ownercheck tp_object_ownercheck
#define object_aclcheck	  tp_object_aclcheck

/* PG16 split check_can_set_role() out of check_is_member_of_role(). */
#define check_can_set_role check_is_member_of_role
#endif

/*
 * PG16: get_extension_schema() became public.  Before that it was a
 * static function in commands/extension.c; this is the same lookup.
 */
#if PG_VERSION_NUM < 160000
#include <access/genam.h>
#include <access/htup_details.h>
#include <access/stratnum.h>
#include <access/table.h>
#include <catalog/pg_extension.h>
#include <utils/fmgroids.h>

static inline Oid
get_extension_schema(Oid ext_oid)
{
	Oid			result;
	Relation	rel;
	SysScanDesc scandesc;
	HeapTuple	tuple;
	ScanKeyData entry[1];

	rel = table_open(ExtensionRelationId, AccessShareLock);
	ScanKeyInit(
			&entry[0],
			Anum_pg_extension_oid,
			BTEqualStrategyNumber,
			F_OIDEQ,
			ObjectIdGetDatum(ext_oid));
	scandesc =
			systable_beginscan(rel, ExtensionOidIndexId, true, NULL, 1, entry);
	tuple = systable_getnext(scandesc);
	if (HeapTupleIsValid(tuple))
		result = ((Form_pg_extension)GETSTRUCT(tuple))->extnamespace;
	else
		result = InvalidOid;
	systable_endscan(scandesc);
	table_close(rel, AccessShareLock);
	return result;
}
#endif

/*
 * PG16: ExtendBufferedRel().  Before it, a caller extended a relation by
 * reading P_NEW under the relation extension lock, which is what
 * nbtree's _bt_getbuf() does on PG15.  Every extension in this code
 * asks for EB_LOCK_FIRST (a new page returned pinned and exclusively
 * locked), so that is the only mode emulated.
 */
#if PG_VERSION_NUM < 160000
#include <storage/bufmgr.h>
#include <storage/lmgr.h>
#include <utils/rel.h>

#define BMR_REL(rel)  (rel)
#define EB_LOCK_FIRST (1 << 2)

static inline Buffer
ExtendBufferedRel(
		Relation			 rel,
		ForkNumber			 forknum,
		BufferAccessStrategy strategy,
		uint32				 flags)
{
	bool   need_lock = !RELATION_IS_LOCAL(rel);
	Buffer buffer;

	Assert(flags == EB_LOCK_FIRST);
	(void)flags;

	if (need_lock)
		LockRelationForExtension(rel, ExclusiveLock);
	buffer = ReadBufferExtended(rel, forknum, P_NEW, RBM_NORMAL, strategy);
	LockBuffer(buffer, BUFFER_LOCK_EXCLUSIVE);
	if (need_lock)
		UnlockRelationForExtension(rel, ExclusiveLock);
	return buffer;
}
#endif

/*
 * PG16: BufFileReadExact(), which raises an error on a short read.
 * Before it, BufFileRead() returned the byte count and left the check
 * to the caller.
 */
#if PG_VERSION_NUM < 160000
#include <storage/buffile.h>

static inline void
BufFileReadExact(BufFile *file, void *ptr, size_t size)
{
	size_t nread = BufFileRead(file, ptr, size);

	if (nread != size)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not read from temporary file: read only %zu "
						"of %zu bytes",
						nread,
						size)));
}
#endif

/* PG16 declares _PG_init() in fmgr.h; declare it for older servers. */
#if PG_VERSION_NUM < 160000
extern PGDLLEXPORT void _PG_init(void);
#endif

/* PG17: foreach_ptr(), copied from nodes/pg_list.h. */
#if PG_VERSION_NUM < 170000
#include <nodes/pg_list.h>

#define foreach_ptr(type, var, lst) foreach_internal(type, *, var, lst, lfirst)
#define foreach_internal(type, pointer, var, lst, func)                    \
	for (type pointer var = 0, pointer var##__outerloop = (type pointer)1; \
		 var##__outerloop;                                                 \
		 var##__outerloop = 0)                                             \
		for (ForEachState var##__state = {(lst), 0};                       \
			 (var##__state.l != NIL &&                                     \
			  var##__state.i < var##__state.l->length &&                   \
			  (var = (type pointer)func(                                   \
					   &var##__state.l->elements[var##__state.i]),         \
			  true));                                                      \
			 var##__state.i++)
#endif

/* PG17: named invalid values for DSA and dshash handles. */
#ifndef DSA_HANDLE_INVALID
#define DSA_HANDLE_INVALID ((dsa_handle)DSM_HANDLE_INVALID)
#endif
#ifndef DSHASH_HANDLE_INVALID
#define DSHASH_HANDLE_INVALID ((dshash_table_handle)InvalidDsaPointer)
#endif

/*
 * PG17: dshash_parameters.copy_function.  Older dshash copies a key with
 * memcpy(), which is what every copy function here does anyway.
 */
#if PG_VERSION_NUM >= 170000
#define TP_DSHASH_SET_COPY_FUNCTION(params, fn) ((params).copy_function = (fn))
#else
#define TP_DSHASH_SET_COPY_FUNCTION(params, fn) ((void)(fn))
#endif

/*
 * PG17: LockHeldByMe() grew an "orstronger" argument.  This is PG17's
 * implementation of it on top of the two-argument form: lock modes are
 * numbered in increasing strength.
 */
#if PG_VERSION_NUM < 170000
#include <storage/lock.h>

static inline bool
tp_lock_held_by_me(const LOCKTAG *locktag, LOCKMODE lockmode, bool orstronger)
{
	if (LockHeldByMe(locktag, lockmode))
		return true;
	if (orstronger)
	{
		for (LOCKMODE mode = lockmode + 1; mode <= MaxLockMode; mode++)
		{
			if (LockHeldByMe(locktag, mode))
				return true;
		}
	}
	return false;
}

#define LockHeldByMe(locktag, lockmode, orstronger) \
	tp_lock_held_by_me(locktag, lockmode, orstronger)
#endif

/* PG17 renamed IsAutoVacuumWorkerProcess(). */
#if PG_VERSION_NUM < 170000
#include <postmaster/autovacuum.h>
#define AmAutoVacuumWorkerProcess() IsAutoVacuumWorkerProcess()
#endif

/*
 * PG17: the MAINTAIN privilege and the pg_maintain role.  Before PG17,
 * the maintenance commands MAINTAIN gates (REINDEX, VACUUM, ANALYZE,
 * CLUSTER, REFRESH MATERIALIZED VIEW, LOCK TABLE) required ownership of
 * the table, and no predefined role granted them.  The checks below
 * reproduce that rule, so this extension enforces what the server
 * itself enforces for the same commands.
 */
#if PG_VERSION_NUM >= 170000
#define tp_class_maintain_aclcheck(relid, roleid) \
	pg_class_aclcheck(relid, roleid, ACL_MAINTAIN)
#define tp_has_pg_maintain(roleid)			  has_privs_of_role(roleid, ROLE_PG_MAINTAIN)
#define TP_RANGE_VAR_CALLBACK_MAINTAINS_TABLE RangeVarCallbackMaintainsTable
#else
#define tp_class_maintain_aclcheck(relid, roleid)         \
	(object_ownercheck(RelationRelationId, relid, roleid) \
			 ? ACLCHECK_OK                                \
			 : ACLCHECK_NOT_OWNER)
#define tp_has_pg_maintain(roleid)			  ((void)(roleid), false)
#define TP_RANGE_VAR_CALLBACK_MAINTAINS_TABLE RangeVarCallbackOwnsTable
#endif
