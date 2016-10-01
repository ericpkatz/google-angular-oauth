angular.module('app', ['ui.router'])
  .config(function($stateProvider, $urlRouterProvider){
    $stateProvider
      .state('home', {
        url: '/',
        templateUrl: '/browser/templates/home.html'
      })
      .state('login', {
        url: '/login',
        templateUrl: '/browser/templates/login.html',
        controller: function($scope, AuthService, $state){
          $scope.login = function(){
            AuthService.login($scope.credentials)
              .then(function(){
                $state.go('home');
              });
          };
        
        }
      });

    $urlRouterProvider.otherwise('/');
  
  });
