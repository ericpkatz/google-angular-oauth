var gulp = require('gulp');
var inject = require('gulp-inject');
var watch = require('gulp-watch');

var _inject = function(){
  var target = gulp.src('./views/layout.html');
  var sources = gulp.src(['browser/app.js', 'browser/**/*.js']);
  target.pipe(inject(sources))
    .pipe(gulp.dest('./views'));
};
gulp.task('inject:js', function(){
  _inject();
});

gulp.task('watch:inject:js', ['inject:js'], function(){
  watch('./browser/**/*.js', function(){
    _inject();
  });

});
