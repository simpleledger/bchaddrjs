/**
 * @license
 * https://github.com/bitcoincashjs/bchaddr
 * Copyright (c) 2018 Emilio Almansi
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

var shell = require('shelljs')
shell.config.fatal = true
var version = require('../package.json').version

shell.rm('-rf', 'dist')
shell.mkdir('-p', 'dist')

shell.exec('npx browserify src/bchaddr.js --s bchaddr', { silent: true })
  .to('dist/bchaddrjs-slp-' + version + '.js')
shell.echo('Generated file: dist/bchaddrjs-slp-' + version + '.js.')

shell.cp('LICENSE.js', 'dist/bchaddrjs-slp-' + version + '.min.js')
shell.exec('cat dist/bchaddrjs-slp-' + version + '.js | npx uglifyjs -c', { silent: true })
  .toEnd('dist/bchaddrjs-slp-' + version + '.min.js')
shell.echo('Generated file: dist/bchaddrjs-slp-' + version + '.min.js.')
