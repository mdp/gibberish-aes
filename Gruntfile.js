/*global module:false*/

module.exports = function(grunt) {
    "use strict";
    var pkg, config;

    pkg = grunt.file.readJSON('package.json');

    config = {
        banner : [
            '/**',
            ' * <%= pkg.name %> v<%= pkg.version %> - <%= grunt.template.today("yyyy-mm-dd") %>',
            ' * <%= pkg.description %>',
            ' *',
            ' * Author: <%= pkg.author %>',
            ' * Copyright: Mark Percival - http://mpercival.com 2008',
            ' *',
            ' * With thanks to:',
            ' * Josh Davis - http://www.josh-davis.org/ecmaScrypt',
            ' * Chris Veness - http://www.movable-type.co.uk/scripts/aes.html',
            ' * Michel I. Gallant - http://www.jensign.com/',
            ' * Jean-Luc Cooke <jlcooke@certainkey.com> 2012-07-12: added strhex + invertArr to compress G2X/G3X/G9X/GBX/GEX/SBox/SBoxInv/Rcon saving over 7KB, and added encString, decString, also made the MD5 routine more easlier compressible using yuicompressor.',
            ' *',
            ' * License: <%= pkg.license %>',
            ' *',
            ' * Usage: GibberishAES.enc("secret", "password")',
            ' * Outputs: AES Encrypted text encoded in Base64',
            ' */\n'
        ].join('\n'),

        pkg : pkg,
        uglifyFiles: {},
        src : 'src/gibberish-aes.js'
    };

    // setup dynamic filenames
    config.versioned = [config.pkg.name, config.pkg.version].join('-').toLowerCase();
    config.dist = ['dist/', '.js'].join(config.versioned);
    config.uglifyFiles[['dist/', '.min.js'].join(config.versioned)] = config.dist;

    // Project configuration.
    grunt.initConfig({
        pkg : config.pkg,
        clean : {
            dist : ['dist/']
        },
        copy: {
            dist: {
                files: [{
                    src: config.src,
                    dest: config.dist
                }]
            }
        },
        uglify : {
            options : { 
                mangle : true,
                banner: config.banner
            },
            dist : {
                files : config.uglifyFiles
            }
        },
        jshint : {
            options : {
                jshintrc : 'jshint.json'
            },
            source : 'src/*.js'
        },
    });

    grunt.loadNpmTasks('grunt-contrib-copy');
    grunt.loadNpmTasks('grunt-contrib-uglify');
    grunt.loadNpmTasks('grunt-contrib-clean');
    grunt.loadNpmTasks('grunt-contrib-jshint');

    // might be nice to add automatic testing eventually
    // grunt.loadNpmTasks('grunt-contrib-jasmine');
    

    grunt.registerTask('build', ['clean', 'jshint', 'copy', 'uglify']);

    // Default task.
    grunt.registerTask('default', ['build']);

    
};