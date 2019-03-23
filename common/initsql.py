SQL="""
CREATE TABLE `asset` (
    `id` INTEGER PRIMARY KEY AUTOINCREMENT,
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
