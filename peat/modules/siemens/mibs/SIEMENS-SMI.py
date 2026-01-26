#
# PySNMP MIB module SIEMENS-SMI (http://snmplabs.com/pysmi)
# ASN.1 source file:///usr/share/snmp/mibs/SIEMENS-SMI.txt
# Produced by pysmi-0.3.1
# Using Python version 3.5.2 (default, Nov 23 2017, 16:37:01)
#
Integer, ObjectIdentifier, OctetString = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
NamedValues, = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
ValueRangeConstraint, ValueSizeConstraint, ConstraintsUnion, SingleValueConstraint, ConstraintsIntersection = mibBuilder.importSymbols("ASN1-REFINEMENT", "ValueRangeConstraint", "ValueSizeConstraint", "ConstraintsUnion", "SingleValueConstraint", "ConstraintsIntersection")
ModuleCompliance, NotificationGroup = mibBuilder.importSymbols("SNMPv2-CONF", "ModuleCompliance", "NotificationGroup")
Integer32, Counter64, MibScalar, MibTable, MibTableRow, MibTableColumn, iso, Counter32, NotificationType, Bits, Gauge32, Unsigned32, enterprises, MibIdentifier, ObjectIdentity, TimeTicks, ModuleIdentity, IpAddress = mibBuilder.importSymbols("SNMPv2-SMI", "Integer32", "Counter64", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "iso", "Counter32", "NotificationType", "Bits", "Gauge32", "Unsigned32", "enterprises", "MibIdentifier", "ObjectIdentity", "TimeTicks", "ModuleIdentity", "IpAddress")
DisplayString, TextualConvention = mibBuilder.importSymbols("SNMPv2-TC", "DisplayString", "TextualConvention")
siemens = ModuleIdentity((1, 3, 6, 1, 4, 1, 22638))
if mibBuilder.loadTexts: siemens.setLastUpdated('200411230913Z')
if mibBuilder.loadTexts: siemens.setOrganization('Siemens')
if mibBuilder.loadTexts: siemens.setContactInfo(' Siemens E-mail: support@siemens.net')
if mibBuilder.loadTexts: siemens.setDescription('The Structure of Management Information for Siemens.')
siprotec = ObjectIdentity((1, 3, 6, 1, 4, 1, 22638, 1))
if mibBuilder.loadTexts: siprotec.setStatus('current')
if mibBuilder.loadTexts: siprotec.setDescription('The root of siprotec device OIDs.')
mibBuilder.exportSymbols("SIEMENS-SMI", siprotec=siprotec, siemens=siemens, PYSNMP_MODULE_ID=siemens)
