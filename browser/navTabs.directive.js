angular.module('app')
  .directive('navTabs', function(){
    return {
      templateUrl: '/browser/templates/navTabs.html',
      controller: function($scope, AuthService, $state){
        $scope.user = AuthService.user;

        $scope.logout = function(){
          AuthService.logout()
            .then(function(){
              $state.go('home');
            });
        };
      }
    };
  });
