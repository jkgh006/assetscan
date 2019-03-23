#!/usr/bin/env python
# -*- coding:utf-8 -*-
import os
import logging, logging.config
LOGGERPATH=os.path.join(os.path.dirname(__file__),"../../log/")
if not os.path.exists(LOGGERPATH):
	os.makedirs(LOGGERPATH)

LOGGING = {
        'version': 1,
        'disable_existing_loggers': True,
        'formatters': {
		'verbose': {
			'format':'%(asctime)s %(levelname)s {%(process)d-%(thread)d %(module)s.%(funcName)s:%(lineno)d} %(message)s',
			'datefmt': '%y-%m-%d %H:%M:%S'
		},
		'simple': {'format': '%(levelname)s %(message)s'},
		'default': {
			'format' : '%(asctime)s %(message)s',
			'datefmt' : '%Y-%m-%d %H:%M:%S'
		}
        },
        'handlers': {
	    'null': {
	        'level':'DEBUG',
		'class':'logging.NullHandler',
   	    },
	    'console':{
		 'level':'DEBUG',
		 'class':'logging.StreamHandler',
		 'formatter': 'default'
	    },

            'file':{
		    'level': 'DEBUG',
                    'class':'logging.handlers.TimedRotatingFileHandler',
                    'filename':os.path.join(os.environ.get('LOG_HOME',''), os.environ.get('LOG_FILE_NAME', os.path.join(LOGGERPATH,'system.log'))),
                    'formatter':'verbose',
		    'encoding' : 'utf8'

            },
        },
	'loggers' : {
		'mylogger' : {
			'level' : 'DEBUG',
			'handlers' : ['file','console'],
			'propagate' : True
		}
	}
    }

if __name__ == '__main__':
	logging.config.dictConfig(LOGGING)
	logger = logging.getLogger('mylogger')
	logger.info('Hello')
