SQL1="""
CREATE TABLE `porttask` (
    `id` INTEGER PRIMARY KEY AUTOINCREMENT,
    `name` varchar(100) DEFAULT NULL,
   `status` INTEGER DEFAULT 0
)
"""
SQL2="""
CREATE TABLE `asset` (
    `id` INTEGER PRIMARY KEY AUTOINCREMENT,
    `taskid` INTEGER DEFAULT NULL,
    `ip` varchar(100) NOT NULL,
    `port` varchar(100) DEFAULT NULL,
    `domain` varchar(100) DEFAULT NULL,
    `banner` varchar(500) DEFAULT NULL,
    `protocol` varchar(100) DEFAULT NULL,
    `service` varchar(200) DEFAULT NULL,
    `assettype` int(10) DEFAULT NULL,
    `position` varchar(200) DEFAULT NULL,
    `proext` varchar(50) DEFAULT NULL
)
"""
SQL3="""
CREATE TABLE `fuzztask` (
    `id` INTEGER PRIMARY KEY AUTOINCREMENT,
    `taskid` INTEGER DEFAULT NULL,
    `assetid` INTEGER DEFAULT NULL,
    `url` varchar(500) DEFAULT NULL,
    `path` varchar(500) DEFAULT NULL,
    `reqcode` INTEGER DEFAULT 0,
    `banner` varchar(500) DEFAULT NULL,
    `reslength` INTEGER DEFAULT 0,
    `status` INTEGER DEFAULT 0
)
"""
