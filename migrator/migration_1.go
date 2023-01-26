package migrator

const migration_1 = `
CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_result_mode_definitions
(
    result_mode TEXT NOT NULL PRIMARY KEY,
    description TEXT
);

INSERT INTO <SCHEMA_PLACEHOLDER>.sk_result_mode_definitions (result_mode, description)
VALUES ('TEST', 'Do process, but do not return the results to cerberus'),
       ('VALIDATION', 'Return to workflow, these orders will not be returned via external api''s'),
       ('PRODUCTION', 'All enabled');

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_connection_modes
(
	name TEXT NOT NULL,
	description TEXT NULL,
	CONSTRAINT sk_pk_connection_modes PRIMARY KEY (name)
);

INSERT INTO <SCHEMA_PLACEHOLDER>.sk_connection_modes(name)
VALUES ('TCP_CLIENT_ONLY'),
       ('TCP_SERVER_ONLY'),
       ('TCP_MIXED'),
       ('FTP_SFTP'),
       ('HTTP');

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_supported_protocols
(
	id uuid NOT NULL DEFAULT uuid_generate_v4(),
	name TEXT NOT NULL UNIQUE,
	description TEXT,
	CONSTRAINT sk_pk_supported_protocols PRIMARY KEY (id)
);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_timezones
(
	zone TEXT NOT NULL,
	CONSTRAINT "sk_pk_timezones" PRIMARY KEY (ZONE)
);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_encodings
(
	encoding TEXT NOT NULL,
	CONSTRAINT "sk_pk_encodings" PRIMARY KEY (ENCODING)
);

INSERT INTO <SCHEMA_PLACEHOLDER>.sk_encodings(ENCODING)
VALUES ('ISO 8859-1'),
('ASCII'),
('DOS852'),
('DOS855'),
('DOS866'),
('ISOLatin1'),
('ISOLatin2'),
('ISOLatin3'),
('ISOLatin4'),
('ISOLatinCyrillic'),
('ISOLatinArabic'),
('ISOLatinGreek'),
('ISOLatinHebrew'),
('ISOLatin5'),
('ISOLatin6'),
('ISOTextComm'),
('HalfWidthKatakana'),
('JISEncoding'),
('ShiftJIS'),
('EUCPkdFmtJapanese'),
('EUCFixWidJapanese'),
('ISO4UnitedKingdom'),
('ISO11SwedishForNames'),
('ISO15Italian'),
('ISO17Spanish'),
('ISO21German'),
('ISO60Norwegian1'),
('ISO69French'),
('ISO10646UTF1'),
('ISO646basic1983'),
('INVARIANT'),
('ISO2IntlRefVersion'),
('NATSSEFI'),
('NATSSEFIADD'),
('NATSDANO'),
('NATSDANOADD'),
('ISO10Swedish'),
('KSC56011987'),
('ISO2022KR'),
('EUCKR'),
('ISO2022JP'),
('ISO2022JP2'),
('ISO13JISC6220jp'),
('ISO14JISC6220ro'),
('ISO16Portuguese'),
('ISO18Greek7Old'),
('ISO19LatinGreek'),
('ISO25French'),
('ISO27LatinGreek1'),
('ISO5427Cyrillic'),
('ISO42JISC62261978'),
('ISO47BSViewdata'),
('ISO49INIS'),
('ISO50INIS8'),
('ISO51INISCyrillic'),
('ISO54271981'),
('ISO5428Greek'),
('ISO57GB1988'),
('ISO58GB231280'),
('ISO61Norwegian2'),
('ISO70VideotexSupp1'),
('ISO84Portuguese2'),
('ISO85Spanish2'),
('ISO86Hungarian'),
('ISO87JISX0208'),
('ISO88Greek7'),
('ISO89ASMO449'),
('ISO90'),
('ISO91JISC62291984a'),
('ISO92JISC62991984b'),
('ISO93JIS62291984badd'),
('ISO94JIS62291984hand'),
('ISO95JIS62291984handadd'),
('ISO96JISC62291984kana'),
('ISO2033'),
('ISO99NAPLPS'),
('ISO102T617bit'),
('ISO103T618bit'),
('ISO111ECMACyrillic'),
('ISO121Canadian1'),
('ISO122Canadian2'),
('ISO123CSAZ24341985gr'),
('ISO88596E'),
('ISO88596I'),
('ISO128T101G2'),
('ISO88598E'),
('ISO88598I'),
('ISO139CSN369103'),
('ISO141JUSIB1002'),
('ISO143IECP271'),
('ISO146Serbian'),
('ISO147Macedonian'),
('ISO150GreekCCITT'),
('ISO151Cuba'),
('ISO6937Add'),
('ISO153GOST1976874'),
('ISO8859Supp'),
('ISO10367Box'),
('ISO158Lap'),
('ISO159JISX02121990'),
('ISO646Danish'),
('USDK'),
('DKUS'),
('KSC5636'),
('Unicode11UTF7'),
('ISO2022CN'),
('ISO2022CNEXT'),
('UTF8'),
('ISO885913'),
('ISO885914'),
('ISO885915'),
('ISO885916'),
('GBK'),
('GB18030'),
('OSDEBCDICDF0415'),
('OSDEBCDICDF03IRV'),
('OSDEBCDICDF041'),
('ISO115481'),
('KZ1048'),
('Unicode'),
('UCS4'),
('UnicodeASCII'),
('UnicodeLatin1'),
('UnicodeJapanese'),
('UnicodeIBM1261'),
('UnicodeIBM1268'),
('UnicodeIBM1276'),
('UnicodeIBM1264'),
('UnicodeIBM1265'),
('Unicode11'),
('SCSU'),
('UTF7'),
('UTF16BE'),
('UTF16LE'),
('UTF16'),
('CESU8'),
('UTF32'),
('UTF32BE'),
('UTF32LE'),
('BOCU1'),
('UTF7IMAP'),
('Windows30Latin1'),
('Windows31Latin1'),
('Windows31Latin2'),
('Windows31Latin5'),
('HPRoman8'),
('AdobeStandardEncoding'),
('VenturaUS'),
('VenturaInternational'),
('DECMCS'),
('PC850Multilingual'),
('PC8DanishNorwegian'),
('PC862LatinHebrew'),
('PC8Turkish'),
('IBMSymbols'),
('IBMThai'),
('HPLegal'),
('HPPiFont'),
('HPMath8'),
('HPPSMath'),
('HPDesktop'),
('VenturaMath'),
('MicrosoftPublishing'),
('Windows31J'),
('GB2312'),
('Big5'),
('Macintosh'),
('IBM037'),
('IBM038'),
('IBM273'),
('IBM274'),
('IBM275'),
('IBM277'),
('IBM278'),
('IBM280'),
('IBM281'),
('IBM284'),
('IBM285'),
('IBM290'),
('IBM297'),
('IBM420'),
('IBM423'),
('IBM424'),
('PC8CodePage437'),
('IBM500'),
('IBM851'),
('PCp852'),
('IBM855'),
('IBM857'),
('IBM860'),
('IBM861'),
('IBM863'),
('IBM864'),
('IBM865'),
('IBM868'),
('IBM869'),
('IBM870'),
('IBM871'),
('IBM880'),
('IBM891'),
('IBM903'),
('IBBM904'),
('IBM905'),
('IBM918'),
('IBM1026'),
('IBMEBCDICATDE'),
('EBCDICATDEA'),
('EBCDICCAFR'),
('EBCDICDKNO'),
('EBCDICDKNOA'),
('EBCDICFISE'),
('EBCDICFISEA'),
('EBCDICFR'),
('EBCDICIT'),
('EBCDICPT'),
('EBCDICES'),
('EBCDICESA'),
('EBCDICESS'),
('EBCDICUK'),
('EBCDICUS'),
('Unknown8BiT'),
('Mnemonic'),
('Mnem'),
('VISCII'),
('VIQR'),
('KOI8R'),
('HZGB2312'),
('IBM866'),
('PC775Baltic'),
('KOI8U'),
('IBM00858'),
('IBM00924'),
('IBM01140'),
('IBM01141'),
('IBM01142'),
('IBM01143'),
('IBM01144'),
('IBM01145'),
('IBM01146'),
('IBM01147'),
('IBM01148'),
('IBM01149'),
('Big5HKSCS'),
('IBM1047'),
('PTCP154'),
('Amiga1251'),
('KOI7switched'),
('BRF'),
('TSCII'),
('CP51932'),
('Windows874'),
('Windows1250'),
('Windows1251'),
('Windows1252'),
('Windows1253'),
('Windows1254'),
('Windows1255'),
('Windows1256'),
('Windows1257'),
('Windows1258'),
('TIS620'),
('CP50220');

INSERT INTO <SCHEMA_PLACEHOLDER>.sk_timezones(zone)
VALUES ('Europe/Andorra'),
       ('Asia/Dubai'),
       ('Asia/Kabul'),
       ('America/Antigua'),
       ('America/Anguilla'),
       ('Europe/Tirane'),
       ('Asia/Yerevan'),
       ('Africa/Luanda'),
       ('Antarctica/McMurdo'),
       ('Antarctica/Casey'),
       ('Antarctica/Davis'),
       ('Antarctica/DumontDUrville'),
       ('Antarctica/Mawson'),
       ('Antarctica/Palmer'),
       ('Antarctica/Rothera'),
       ('Antarctica/Syowa'),
       ('Antarctica/Troll'),
       ('Antarctica/Vostok'),
       ('America/Argentina/Buenos_Aires'),
       ('America/Argentina/Cordoba'),
       ('America/Argentina/Salta'),
       ('America/Argentina/Jujuy'),
       ('America/Argentina/Tucuman'),
       ('America/Argentina/Catamarca'),
       ('America/Argentina/La_Rioja'),
       ('America/Argentina/San_Juan'),
       ('America/Argentina/Mendoza'),
       ('America/Argentina/San_Luis'),
       ('America/Argentina/Rio_Gallegos'),
       ('America/Argentina/Ushuaia'),
       ('Pacific/Pago_Pago'),
       ('Europe/Vienna'),
       ('Australia/Lord_Howe'),
       ('Antarctica/Macquarie'),
       ('Australia/Hobart'),
       ('Australia/Melbourne'),
       ('Australia/Sydney'),
       ('Australia/Broken_Hill'),
       ('Australia/Brisbane'),
       ('Australia/Lindeman'),
       ('Australia/Adelaide'),
       ('Australia/Darwin'),
       ('Australia/Perth'),
       ('Australia/Eucla'),
       ('America/Aruba'),
       ('Europe/Mariehamn'),
       ('Asia/Baku'),
       ('Europe/Sarajevo'),
       ('America/Barbados'),
       ('Asia/Dhaka'),
       ('Europe/Brussels'),
       ('Africa/Ouagadougou'),
       ('Europe/Sofia'),
       ('Asia/Bahrain'),
       ('Africa/Bujumbura'),
       ('Africa/Porto-Novo'),
       ('America/St_Barthelemy'),
       ('Atlantic/Bermuda'),
       ('Asia/Brunei'),
       ('America/La_Paz'),
       ('America/Kralendijk'),
       ('America/Noronha'),
       ('America/Belem'),
       ('America/Fortaleza'),
       ('America/Recife'),
       ('America/Araguaina'),
       ('America/Maceio'),
       ('America/Bahia'),
       ('America/Sao_Paulo'),
       ('America/Campo_Grande'),
       ('America/Cuiaba'),
       ('America/Santarem'),
       ('America/Porto_Velho'),
       ('America/Boa_Vista'),
       ('America/Manaus'),
       ('America/Eirunepe'),
       ('America/Rio_Branco'),
       ('America/Nassau'),
       ('Asia/Thimphu'),
       ('Africa/Gaborone'),
       ('Europe/Minsk'),
       ('America/Belize'),
       ('America/St_Johns'),
       ('America/Halifax'),
       ('America/Glace_Bay'),
       ('America/Moncton'),
       ('America/Goose_Bay'),
       ('America/Blanc-Sablon'),
       ('America/Toronto'),
       ('America/Nipigon'),
       ('America/Thunder_Bay'),
       ('America/Iqaluit'),
       ('America/Pangnirtung'),
       ('America/Atikokan'),
       ('America/Winnipeg'),
       ('America/Rainy_River'),
       ('America/Resolute'),
       ('America/Rankin_Inlet'),
       ('America/Regina'),
       ('America/Swift_Current'),
       ('America/Edmonton'),
       ('America/Cambridge_Bay'),
       ('America/Yellowknife'),
       ('America/Inuvik'),
       ('America/Creston'),
       ('America/Dawson_Creek'),
       ('America/Fort_Nelson'),
       ('America/Whitehorse'),
       ('America/Dawson'),
       ('America/Vancouver'),
       ('Indian/Cocos'),
       ('Africa/Kinshasa'),
       ('Africa/Lubumbashi'),
       ('Africa/Bangui'),
       ('Africa/Brazzaville'),
       ('Europe/Zurich'),
       ('Africa/Abidjan'),
       ('Pacific/Rarotonga'),
       ('America/Santiago'),
       ('America/Punta_Arenas'),
       ('Pacific/Easter'),
       ('Africa/Douala'),
       ('Asia/Shanghai'),
       ('Asia/Urumqi'),
       ('America/Bogota'),
       ('America/Costa_Rica'),
       ('America/Havana'),
       ('Atlantic/Cape_Verde'),
       ('America/Curacao'),
       ('Indian/Christmas'),
       ('Asia/Nicosia'),
       ('Asia/Famagusta'),
       ('Europe/Prague'),
       ('Europe/Berlin'),
       ('Europe/Busingen'),
       ('Africa/Djibouti'),
       ('Europe/Copenhagen'),
       ('America/Dominica'),
       ('America/Santo_Domingo'),
       ('Africa/Algiers'),
       ('America/Guayaquil'),
       ('Pacific/Galapagos'),
       ('Europe/Tallinn'),
       ('Africa/Cairo'),
       ('Africa/El_Aaiun'),
       ('Africa/Asmara'),
       ('Europe/Madrid'),
       ('Africa/Ceuta'),
       ('Atlantic/Canary'),
       ('Africa/Addis_Ababa'),
       ('Europe/Helsinki'),
       ('Pacific/Fiji'),
       ('Atlantic/Stanley'),
       ('Pacific/Chuuk'),
       ('Pacific/Pohnpei'),
       ('Pacific/Kosrae'),
       ('Atlantic/Faroe'),
       ('Europe/Paris'),
       ('Africa/Libreville'),
       ('Europe/London'),
       ('America/Grenada'),
       ('Asia/Tbilisi'),
       ('America/Cayenne'),
       ('Europe/Guernsey'),
       ('Africa/Accra'),
       ('Europe/Gibraltar'),
       ('America/Nuuk'),
       ('America/Danmarkshavn'),
       ('America/Scoresbysund'),
       ('America/Thule'),
       ('Africa/Banjul'),
       ('Africa/Conakry'),
       ('America/Guadeloupe'),
       ('Africa/Malabo'),
       ('Europe/Athens'),
       ('Atlantic/South_Georgia'),
       ('America/Guatemala'),
       ('Pacific/Guam'),
       ('Africa/Bissau'),
       ('America/Guyana'),
       ('Asia/Hong_Kong'),
       ('America/Tegucigalpa'),
       ('Europe/Zagreb'),
       ('America/Port-au-Prince'),
       ('Europe/Budapest'),
       ('Asia/Jakarta'),
       ('Asia/Pontianak'),
       ('Asia/Makassar'),
       ('Asia/Jayapura'),
       ('Europe/Dublin'),
       ('Asia/Jerusalem'),
       ('Europe/Isle_of_Man'),
       ('Asia/Kolkata'),
       ('Indian/Chagos'),
       ('Asia/Baghdad'),
       ('Asia/Tehran'),
       ('Atlantic/Reykjavik'),
       ('Europe/Rome'),
       ('Europe/Jersey'),
       ('America/Jamaica'),
       ('Asia/Amman'),
       ('Asia/Tokyo'),
       ('Africa/Nairobi'),
       ('Asia/Bishkek'),
       ('Asia/Phnom_Penh'),
       ('Pacific/Tarawa'),
       ('Pacific/Kanton'),
       ('Pacific/Kiritimati'),
       ('Indian/Comoro'),
       ('America/St_Kitts'),
       ('Asia/Pyongyang'),
       ('Asia/Seoul'),
       ('Asia/Kuwait'),
       ('America/Cayman'),
       ('Asia/Almaty'),
       ('Asia/Qyzylorda'),
       ('Asia/Qostanay'),
       ('Asia/Aqtobe'),
       ('Asia/Aqtau'),
       ('Asia/Atyrau'),
       ('Asia/Oral'),
       ('Asia/Vientiane'),
       ('Asia/Beirut'),
       ('America/St_Lucia'),
       ('Europe/Vaduz'),
       ('Asia/Colombo'),
       ('Africa/Monrovia'),
       ('Africa/Maseru'),
       ('Europe/Vilnius'),
       ('Europe/Luxembourg'),
       ('Europe/Riga'),
       ('Africa/Tripoli'),
       ('Africa/Casablanca'),
       ('Europe/Monaco'),
       ('Europe/Chisinau'),
       ('Europe/Podgorica'),
       ('America/Marigot'),
       ('Indian/Antananarivo'),
       ('Pacific/Majuro'),
       ('Pacific/Kwajalein'),
       ('Europe/Skopje'),
       ('Africa/Bamako'),
       ('Asia/Yangon'),
       ('Asia/Ulaanbaatar'),
       ('Asia/Hovd'),
       ('Asia/Choibalsan'),
       ('Asia/Macau'),
       ('Pacific/Saipan'),
       ('America/Martinique'),
       ('Africa/Nouakchott'),
       ('America/Montserrat'),
       ('Europe/Malta'),
       ('Indian/Mauritius'),
       ('Indian/Maldives'),
       ('Africa/Blantyre'),
       ('America/Mexico_City'),
       ('America/Cancun'),
       ('America/Merida'),
       ('America/Monterrey'),
       ('America/Matamoros'),
       ('America/Mazatlan'),
       ('America/Chihuahua'),
       ('America/Ojinaga'),
       ('America/Hermosillo'),
       ('America/Tijuana'),
       ('America/Bahia_Banderas'),
       ('Asia/Kuala_Lumpur'),
       ('Asia/Kuching'),
       ('Africa/Maputo'),
       ('Africa/Windhoek'),
       ('Pacific/Noumea'),
       ('Africa/Niamey'),
       ('Pacific/Norfolk'),
       ('Africa/Lagos'),
       ('America/Managua'),
       ('Europe/Amsterdam'),
       ('Europe/Oslo'),
       ('Asia/Kathmandu'),
       ('Pacific/Nauru'),
       ('Pacific/Niue'),
       ('Pacific/Auckland'),
       ('Pacific/Chatham'),
       ('Asia/Muscat'),
       ('America/Panama'),
       ('America/Lima'),
       ('Pacific/Tahiti'),
       ('Pacific/Marquesas'),
       ('Pacific/Gambier'),
       ('Pacific/Port_Moresby'),
       ('Pacific/Bougainville'),
       ('Asia/Manila'),
       ('Asia/Karachi'),
       ('Europe/Warsaw'),
       ('America/Miquelon'),
       ('Pacific/Pitcairn'),
       ('America/Puerto_Rico'),
       ('Asia/Gaza'),
       ('Asia/Hebron'),
       ('Europe/Lisbon'),
       ('Atlantic/Madeira'),
       ('Atlantic/Azores'),
       ('Pacific/Palau'),
       ('America/Asuncion'),
       ('Asia/Qatar'),
       ('Indian/Reunion'),
       ('Europe/Bucharest'),
       ('Europe/Belgrade'),
       ('Europe/Kaliningrad'),
       ('Europe/Moscow'),
       ('Europe/Simferopol'),
       ('Europe/Kirov'),
       ('Europe/Volgograd'),
       ('Europe/Astrakhan'),
       ('Europe/Saratov'),
       ('Europe/Ulyanovsk'),
       ('Europe/Samara'),
       ('Asia/Yekaterinburg'),
       ('Asia/Omsk'),
       ('Asia/Novosibirsk'),
       ('Asia/Barnaul'),
       ('Asia/Tomsk'),
       ('Asia/Novokuznetsk'),
       ('Asia/Krasnoyarsk'),
       ('Asia/Irkutsk'),
       ('Asia/Chita'),
       ('Asia/Yakutsk'),
       ('Asia/Khandyga'),
       ('Asia/Vladivostok'),
       ('Asia/Ust-Nera'),
       ('Asia/Magadan'),
       ('Asia/Sakhalin'),
       ('Asia/Srednekolymsk'),
       ('Asia/Kamchatka'),
       ('Asia/Anadyr'),
       ('Africa/Kigali'),
       ('Asia/Riyadh'),
       ('Pacific/Guadalcanal'),
       ('Indian/Mahe'),
       ('Africa/Khartoum'),
       ('Europe/Stockholm'),
       ('Asia/Singapore'),
       ('Atlantic/St_Helena'),
       ('Europe/Ljubljana'),
       ('Arctic/Longyearbyen'),
       ('Europe/Bratislava'),
       ('Africa/Freetown'),
       ('Europe/San_Marino'),
       ('Africa/Dakar'),
       ('Africa/Mogadishu'),
       ('America/Paramaribo'),
       ('Africa/Juba'),
       ('Africa/Sao_Tome'),
       ('America/El_Salvador'),
       ('America/Lower_Princes'),
       ('Asia/Damascus'),
       ('Africa/Mbabane'),
       ('America/Grand_Turk'),
       ('Africa/Ndjamena'),
       ('Indian/Kerguelen'),
       ('Africa/Lome'),
       ('Asia/Bangkok'),
       ('Asia/Dushanbe'),
       ('Pacific/Fakaofo'),
       ('Asia/Dili'),
       ('Asia/Ashgabat'),
       ('Africa/Tunis'),
       ('Pacific/Tongatapu'),
       ('Europe/Istanbul'),
       ('America/Port_of_Spain'),
       ('Pacific/Funafuti'),
       ('Asia/Taipei'),
       ('Africa/Dar_es_Salaam'),
       ('Europe/Kiev'),
       ('Europe/Uzhgorod'),
       ('Europe/Zaporozhye'),
       ('Africa/Kampala'),
       ('Pacific/Midway'),
       ('Pacific/Wake'),
       ('America/New_York'),
       ('America/Detroit'),
       ('America/Kentucky/Louisville'),
       ('America/Kentucky/Monticello'),
       ('America/Indiana/Indianapolis'),
       ('America/Indiana/Vincennes'),
       ('America/Indiana/Winamac'),
       ('America/Indiana/Marengo'),
       ('America/Indiana/Petersburg'),
       ('America/Indiana/Vevay'),
       ('America/Chicago'),
       ('America/Indiana/Tell_City'),
       ('America/Indiana/Knox'),
       ('America/Menominee'),
       ('America/North_Dakota/Center'),
       ('America/North_Dakota/New_Salem'),
       ('America/North_Dakota/Beulah'),
       ('America/Denver'),
       ('America/Boise'),
       ('America/Phoenix'),
       ('America/Los_Angeles'),
       ('America/Anchorage'),
       ('America/Juneau'),
       ('America/Sitka'),
       ('America/Metlakatla'),
       ('America/Yakutat'),
       ('America/Nome'),
       ('America/Adak'),
       ('Pacific/Honolulu'),
       ('America/Montevideo'),
       ('Asia/Samarkand'),
       ('Asia/Tashkent'),
       ('Europe/Vatican'),
       ('America/St_Vincent'),
       ('America/Caracas'),
       ('America/Tortola'),
       ('America/St_Thomas'),
       ('Asia/Ho_Chi_Minh'),
       ('Pacific/Efate'),
       ('Pacific/Wallis'),
       ('Pacific/Apia'),
       ('Asia/Aden'),
       ('Indian/Mayotte'),
       ('Africa/Johannesburg'),
       ('Africa/Lusaka'),
       ('Africa/Harare');

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_instruments
(
	id uuid NOT NULL,
	protocol_id uuid NOT NULL,
	"name" TEXT NOT NULL,
	hostname TEXT NOT NULL,
	client_port int,
	enabled bool NOT NULL DEFAULT FALSE,
	connection_mode TEXT NOT NULL,
	running_mode TEXT NOT NULL,
	captureresults bool NOT NULL DEFAULT TRUE,
	capturediagnostics bool NOT NULL DEFAULT TRUE,
	replytoquery bool NOT NULL DEFAULT FALSE,
	status TEXT NOT NULL DEFAULT 'OFFLINE',
	sent_to_cerberus bool NOT NULL DEFAULT FALSE,
	timezone TEXT NOT NULL DEFAULT 'Europe/Berlin',
	file_encoding TEXT NOT NULL DEFAULT 'ASCII',
	created_at timestamp NOT NULL DEFAULT timezone('utc', now()),
    modified_at timestamp NULL,
	deleted_at timestamp NULL,
	CONSTRAINT sk_pk_instruments PRIMARY KEY (id),
	CONSTRAINT sk_fk_connection_mode_instruments FOREIGN KEY (connection_mode) REFERENCES <SCHEMA_PLACEHOLDER>.sk_connection_modes (name),
	CONSTRAINT sk_fk_result_mode__instruments FOREIGN KEY (running_mode) REFERENCES <SCHEMA_PLACEHOLDER>.sk_result_mode_definitions (result_mode),
	CONSTRAINT sk_fk_supported_protocol__instruments FOREIGN KEY (protocol_id) REFERENCES <SCHEMA_PLACEHOLDER>.sk_supported_protocols (id),
	CONSTRAINT sk_fk_timezone__zone FOREIGN KEY (timezone) REFERENCES <SCHEMA_PLACEHOLDER>.sk_timezones (ZONE),
	CONSTRAINT sk_fk_encoding__encoding FOREIGN KEY (file_encoding) REFERENCES <SCHEMA_PLACEHOLDER>.sk_encodings (ENCODING)
);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_result_type_definitions
(
	type TEXT NOT NULL,
	CONSTRAINT "sk_pk_result_type_definitions" PRIMARY KEY (type)
);

INSERT INTO <SCHEMA_PLACEHOLDER>.sk_result_type_definitions(type)
VALUES ('int'),
       ('decimal'),
       ('boundedDecimal'),
       ('string'),
       ('pein'),
       ('react'),
       ('invalid'),
       ('enum');

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_analyte_mappings
(
	id uuid NOT NULL DEFAULT uuid_generate_v4(),
	instrument_id uuid NOT NULL,
	instrument_analyte TEXT NOT NULL,
	analyte_id uuid NOT NULL,
	result_type TEXT NOT NULL,
	created_at timestamp DEFAULT timezone('utc', now()),
	modified_at timestamp,
	deleted_at timestamp,
	CONSTRAINT sk_pk_analyte_mappings PRIMARY KEY (id),
	CONSTRAINT sk_fk_analyte_id_instruments_id FOREIGN KEY (instrument_id) REFERENCES <SCHEMA_PLACEHOLDER>.sk_instruments (id),
	CONSTRAINT sk_fk_analyte_mappings_result_type_definition FOREIGN KEY (result_type) REFERENCES <SCHEMA_PLACEHOLDER>.sk_result_type_definitions (TYPE)
);

CREATE UNIQUE INDEX sk_un_analyte_mapping_instrument_id_instrument_analyte ON
<SCHEMA_PLACEHOLDER>.sk_analyte_mappings(
	instrument_id,
	instrument_analyte
)
WHERE
deleted_at IS NULL;

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_channel_mappings
(
	id uuid NOT NULL DEFAULT uuid_generate_v4(),
	instrument_channel TEXT NOT NULL,
	channel_id uuid NOT NULL,
	analyte_mapping_id uuid NOT NULL,
	created_at timestamp DEFAULT timezone('utc', now()),
    modified_at timestamp,
	deleted_at timestamp,
	CONSTRAINT "sk_pk_channel_mapping_id" PRIMARY KEY (id),
	CONSTRAINT "sk_fk_analyte_mapping_id__id" FOREIGN KEY (analyte_mapping_id) REFERENCES <SCHEMA_PLACEHOLDER>.sk_analyte_mappings (id)
);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_result_mappings
(
	id uuid NOT NULL DEFAULT uuid_generate_v4(),
	analyte_mapping_id uuid NOT NULL,
	"key" TEXT NOT NULL,
	value TEXT NOT NULL,
	"index" int DEFAULT 1,
	created_at timestamp DEFAULT timezone('utc', now()),
	modified_at timestamp,
	deleted_at timestamp,
	CONSTRAINT "sk_pk_result_mapping_id" PRIMARY KEY (id),
	CONSTRAINT "sk_fk_analyte_mapping_id__id" FOREIGN KEY (analyte_mapping_id) REFERENCES <SCHEMA_PLACEHOLDER>.sk_analyte_mappings (id)
);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_analysis_requests
(
	id uuid NOT NULL DEFAULT uuid_generate_v4(),
	work_item_id uuid NOT NULL,
	analyte_id uuid NOT NULL,
	sample_code TEXT NOT NULL,
	material_id uuid NOT NULL,
	laboratory_id uuid NOT NULL,
	valid_until_time timestamp NOT NULL,
	created_at timestamp NOT NULL DEFAULT timezone('utc', now()),
	CONSTRAINT sk_pk_analysis_requests PRIMARY KEY (id),
	CONSTRAINT "sk_unique_workitem_id" UNIQUE (work_item_id)
);

CREATE INDEX sk_idx_created_at_analysis_requests ON
<SCHEMA_PLACEHOLDER>.sk_analysis_requests (
	created_at ASC
);

CREATE INDEX sk_idx_sample_code_analysis_requests ON
<SCHEMA_PLACEHOLDER>.sk_analysis_requests (
	sample_code ASC
);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_subject_infos(
	id uuid not null default uuid_generate_v4(),
    analysis_request_id uuid not null,
	"type" varchar,
	date_of_birth timestamp,
	first_name varchar,
	last_name varchar,
	donor_id varchar,
	donation_id varchar,
	donation_type varchar,
	pseudonym varchar,
    constraint sk_pk_subject_infos primary key (id),
    constraint sk_fk_subject_infos_analysis_requests foreign key (analysis_request_id) references <SCHEMA_PLACEHOLDER>.sk_analysis_requests(id)
);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_request_mappings
(
	id uuid NOT NULL DEFAULT uuid_generate_v4(),
	code TEXT NOT NULL,
	instrument_id uuid NOT NULL,
	created_at timestamp DEFAULT timezone('utc', now()),
    modified_at timestamp,
    deleted_at timestamp,
	CONSTRAINT "sk_pk_request_mappings" PRIMARY KEY (id),
	CONSTRAINT "sk_fk_instrument_id__id" FOREIGN KEY (instrument_id) REFERENCES <SCHEMA_PLACEHOLDER>.sk_instruments (id)
);

CREATE UNIQUE INDEX sk_un_request_mappings_code_insturment_id ON <SCHEMA_PLACEHOLDER>.sk_request_mappings USING btree (code, instrument_id) WHERE (deleted_at IS NULL);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_request_mapping_analytes
(
	id uuid NOT NULL DEFAULT uuid_generate_v4(),
	analyte_id uuid NOT NULL,
	request_mapping_id uuid NOT NULL,
	created_at timestamp DEFAULT timezone('utc', now()),
    modified_at timestamp,
    deleted_at timestamp,
	CONSTRAINT "sk_pk_request_mapping_analyte_id" PRIMARY KEY (id),
	CONSTRAINT "sk_fk_request_mapping_id__id" FOREIGN KEY (request_mapping_id) REFERENCES <SCHEMA_PLACEHOLDER>.sk_request_mappings (id),
    CONSTRAINT "sk_unique_request_mapping_analytes" UNIQUE (request_mapping_id, analyte_id)
);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_request_mapping_sent
(
	id uuid NOT NULL DEFAULT uuid_generate_v4(),
	sample_code TEXT NOT NULL,
	request_mapping_id uuid NOT NULL,
	created_at timestamp DEFAULT timezone('utc', now()),
	CONSTRAINT "sk_pk_request_mapping_sent_id" PRIMARY KEY (id),
	CONSTRAINT "sk_fk_request_mapping_id__id" FOREIGN KEY (request_mapping_id) REFERENCES <SCHEMA_PLACEHOLDER>.sk_request_mappings (id)
);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_analysis_results
(
	id uuid NOT NULL DEFAULT uuid_generate_v4(),
	analyte_mapping_id uuid NOT NULL,
	instrument_id uuid NOT NULL,
    sample_code TEXT NOT NULL,
	instrument_run_id uuid NOT NULL,
    result_record_id uuid NOT NULL,
    batch_id uuid NOT NULL DEFAULT('00000000-0000-0000-0000-000000000000'),
	"result" varchar NOT NULL,
    status varchar NOT NULL,
    result_mode TEXT NOT NULL,
    yielded_at timestamp NOT NULL,
    valid_until timestamp NOT NULL,
    operator varchar NOT NULL,
    technical_release_datetime timestamp NOT NULL,
    run_counter int NOT NULL DEFAULT 0,
    edited bool NOT NULL,
    edit_reason varchar,
	CONSTRAINT sk_pk_analysis_result PRIMARY KEY (id),
    CONSTRAINT sk_fk_running_mode__analysis_results FOREIGN KEY (result_mode) REFERENCES <SCHEMA_PLACEHOLDER>.sk_result_mode_definitions (result_mode)
);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_channel_results
(
	id uuid NOT NULL DEFAULT uuid_generate_v4(),
	analysis_result_id uuid NOT NULL,
	channel_id uuid NOT NULL,
    qualitative_result varchar NOT NULL,
	qualitative_result_edited bool NOT NULL,
	CONSTRAINT sk_pk_channel_results PRIMARY KEY (id),
    CONSTRAINT sk_fk_channel_results_analysis_result FOREIGN KEY (analysis_result_id) REFERENCES <SCHEMA_PLACEHOLDER>.sk_analysis_results(id)
);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_channel_result_quantitative_values(
    id uuid NOT NULL DEFAULT uuid_generate_v4(),
	channel_result_id uuid NOT NULL,
	metric varchar NOT NULL,
	"value" varchar NOT NULL,
    CONSTRAINT sk_pk_channel_result_quantitative_values PRIMARY KEY (id),
    CONSTRAINT sk_fk_channel_result_quantitative_values_channel_result FOREIGN KEY (channel_result_id) REFERENCES <SCHEMA_PLACEHOLDER>.sk_channel_results(id)
);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_analysis_result_extravalues(
	id uuid NOT NULL DEFAULT uuid_generate_v4(),
	analysis_result_id uuid NOT NULL,
	"key" varchar NOT NULL,
	"value" varchar NOT NULL,
    CONSTRAINT sk_pk_analysis_result_extravalues PRIMARY KEY (id),
    CONSTRAINT sk_fk_analysis_result_extravalues_analysis_result FOREIGN KEY (analysis_result_id) REFERENCES <SCHEMA_PLACEHOLDER>.sk_analysis_results(id)
);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_analysis_result_reagent_infos(
	id uuid NOT NULL DEFAULT uuid_generate_v4(),
	analysis_result_id uuid NOT NULL,
	serial varchar NOT NULL,
	"name" varchar NOT NULL, 
	code varchar NOT NULL,
	shelf_life timestamp NOT NULL,
	lot_no varchar NOT NULL,
	manufacturer_name varchar NOT NULL,
	reagent_manufacturer_date timestamp NOT NULL,
	reagent_type varchar NOT NULL,
	use_until timestamp NOT NULL,
	date_created timestamp NOT NULL DEFAULT timezone('utc', now()),
    CONSTRAINT sk_pk_analysis_result_reagent_infos PRIMARY KEY (id),
    CONSTRAINT sk_fk_analysis_result_reagent_infos_analysis_result FOREIGN KEY (analysis_result_id) REFERENCES <SCHEMA_PLACEHOLDER>.sk_analysis_results(id)
);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_analysis_result_images(
	id uuid NOT NULL DEFAULT uuid_generate_v4(),
	analysis_result_id uuid NOT NULL,
    channel_result_id uuid,
	name varchar NOT NULL,
	description varchar,
    CONSTRAINT sk_pk_analysis_result_images PRIMARY KEY (id),
    CONSTRAINT sk_fk_analysis_result_images_analysis_result FOREIGN KEY (analysis_result_id) REFERENCES <SCHEMA_PLACEHOLDER>.sk_analysis_results(id),
    CONSTRAINT sk_fk_analysis_result_images_channel_result FOREIGN KEY (channel_result_id) REFERENCES <SCHEMA_PLACEHOLDER>.sk_channel_results(id)
);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_analysis_result_warnings(
	id uuid NOT NULL DEFAULT uuid_generate_v4(),
	analysis_result_id uuid NOT NULL,
    warning varchar NOT NULL,
    CONSTRAINT sk_pk_analysis_result_warnings PRIMARY KEY (id),
    CONSTRAINT sk_fk_analysis_result_warnings_analysis_result FOREIGN KEY (analysis_result_id) REFERENCES <SCHEMA_PLACEHOLDER>.sk_analysis_results(id)
);

CREATE INDEX sk_analysis_result_batch_id ON
<SCHEMA_PLACEHOLDER>.sk_analysis_results (batch_id);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_cia_http_history
(
	id uuid NOT NULL DEFAULT uuid_generate_v4(),
	"type" varchar NOT NULL,
	status_code int DEFAULT 0,
	response_body TEXT,
	request_body TEXT NOT NULL,
	created_at timestamp NOT NULL DEFAULT timezone('utc', now()),
	CONSTRAINT pk_cia_history_id_id PRIMARY KEY (id)
);

CREATE INDEX cia_http_history_created_at ON
<SCHEMA_PLACEHOLDER>.sk_cia_http_history (created_at);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_cia_http_history_analysis_request_ids
(
	cia_http_history_id uuid NOT NULL REFERENCES <SCHEMA_PLACEHOLDER>.sk_cia_http_history (id),
	analysis_request_id uuid NOT NULL REFERENCES <SCHEMA_PLACEHOLDER>.sk_analysis_requests (id)
);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_cia_http_history_analysis_result_ids
(
	cia_http_history_id uuid NOT NULL REFERENCES <SCHEMA_PLACEHOLDER>.sk_cia_http_history (id),
	analysis_result_id uuid NOT NULL REFERENCES <SCHEMA_PLACEHOLDER>.sk_analysis_results (id)
);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_instrument_request_upload_log
(
	id uuid NOT NULL DEFAULT uuid_generate_v4(),
	instrument_id uuid NOT NULL,
	analysis_request_id uuid NOT NULL,
	status TEXT NOT NULL,
	tcp_send_message TEXT NOT NULL,
	send_date timestamp NULL,
	created_at timestamp DEFAULT timezone('utc', now()),
	CONSTRAINT "sk_pk_instrument_request_upload_log_id" PRIMARY KEY (id),
	CONSTRAINT "sk_fk_transfer_instrument__id" FOREIGN KEY (instrument_id) REFERENCES <SCHEMA_PLACEHOLDER>.sk_instruments (id),
	CONSTRAINT "sk_fk_transfer_analysis_request_id__id" FOREIGN KEY (analysis_request_id) REFERENCES <SCHEMA_PLACEHOLDER>.sk_analysis_requests (id)
);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_protocol_abilities
(
    id uuid NOT NULL DEFAULT uuid_generate_v4(),
	protocol_id uuid NOT NULL,
	connection_mode TEXT NOT NULL,
    abilities TEXT NOT NULL,
	request_mapping_available bool NOT NULL DEFAULT FALSE,
	created_at timestamp DEFAULT timezone('utc', now()),
	modified_at timestamp,
    deleted_at timestamp,
	CONSTRAINT "sk_pk_protocol_abilities" PRIMARY KEY (id),
	CONSTRAINT "sk_fk_protocol_id__id" FOREIGN KEY (protocol_id) REFERENCES <SCHEMA_PLACEHOLDER>.sk_supported_protocols (id)
);

CREATE UNIQUE INDEX sk_un_protocol_abilities ON <SCHEMA_PLACEHOLDER>.sk_protocol_abilities (protocol_id, connection_mode, deleted_at);

CREATE TABLE <SCHEMA_PLACEHOLDER>.sk_cerberus_queue_items
(
    queue_item_id uuid NOT NULL DEFAULT uuid_generate_v4(),
    json_message TEXT NOT NULL,
    last_http_status INT NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '', 
    last_error_at TIMESTAMP,
    trial_count INT NOT NULL DEFAULT 0,
    retry_not_before TIMESTAMP NOT NULL DEFAULT timezone('utc', now()),
    raw_response TEXT NOT NULL DEFAULT '',
    response_json_message TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT timezone('utc', now()),
    CONSTRAINT "sk_pk_cerberus_queue_items" PRIMARY KEY (queue_item_id)
);

CREATE INDEX sk_idx_cerberus_queue_items_created_at ON <SCHEMA_PLACEHOLDER>.sk_cerberus_queue_items (created_at);
CREATE INDEX sk_analysis_result_analyte_mapping_id ON <SCHEMA_PLACEHOLDER>.sk_analysis_results USING btree (analyte_mapping_id);
CREATE INDEX sk_analysis_result_analyte_sample_code ON <SCHEMA_PLACEHOLDER>.sk_analysis_results USING btree (sample_code);
CREATE UNIQUE INDEX sk_un_analyte_mapping_analyte_id ON <SCHEMA_PLACEHOLDER>.sk_analyte_mappings USING btree (instrument_id, instrument_analyte) WHERE (deleted_at IS NULL);
CREATE UNIQUE INDEX sk_un_result_images_result_id ON <SCHEMA_PLACEHOLDER>.sk_analysis_result_images USING btree (analysis_result_id);
CREATE UNIQUE INDEX sk_un_result_images_result_id_channel_result ON <SCHEMA_PLACEHOLDER>.sk_analysis_result_images USING btree (analysis_result_id, channel_result_id);
CREATE INDEX sk_cerberus_queue_items_created_at ON <SCHEMA_PLACEHOLDER>.sk_cerberus_queue_items USING btree (created_at);
CREATE INDEX sk_cerberus_queue_items_retry_not_before ON <SCHEMA_PLACEHOLDER>.sk_cerberus_queue_items USING btree (retry_not_before);`
