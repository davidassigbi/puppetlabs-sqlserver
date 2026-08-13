##
# @summary Define Resource Type: sqlserver::login::permissions#
#
# Requirement/Dependencies:
# Requires defined type {sqlserver::config} in order to execute against the SQL Server instance
#
#
# @param login
#   The login for which the permission will be manage.
#
# @param permissions
#   An array of permissions you would like managed. i.e. ['SELECT', 'INSERT', 'UPDATE', 'DELETE']
#
# @param state
#   The state you would like the permission in.
#   Accepts 'GRANT', 'DENY', 'REVOKE'.
#   Please note that REVOKE equates to absent and will default to database and system level permissions.
#
# @param instance
#   The name of the instance where the user and database exists. Defaults to 'MSSQLSERVER'
# 
# @param with_grant_option
#   Bolean value that allows user to grant options.
#
# @param securable
#   Optional server-scoped securable to scope the permission to, e.g.
#   'LOGIN::[sa]' or 'ENDPOINT::[Mirroring]'. When undef (default) the
#   permission is server-wide (`GRANT <perm> TO [<login>]`). When set, the
#   grant becomes object-scoped (`GRANT <perm> ON <securable> TO [<login>]`).
#   The value is interpolated verbatim into the T-SQL — the caller is
#   responsible for supplying valid securable syntax. Note: in this first cut
#   the onlyif guard is not filtered by securable for the server path, so a
#   differing grant state on any securable may trigger a spurious corrective
#   run — safe, just not optimally idempotent.
#
##
define sqlserver::login::permissions (
  String[1,128] $login,
  Array[String[4,128]] $permissions,
  Pattern[/(?i)^(GRANT|REVOKE|DENY)$/] $state = 'GRANT',
  Boolean $with_grant_option                  = false,
  String[1,16] $instance                      = 'MSSQLSERVER',
  Optional[String] $securable                 = undef,
) {
  sqlserver_validate_instance_name($instance)

  $_state = upcase($state)

  $_grant_option =  $with_grant_option ? {
    true => '-WITH_GRANT_OPTION',
    default => ''
  }

  $create_login_permission_parameters = {
    'permissions'       => $permissions,
    'with_grant_option' => $with_grant_option,
    'login'             => $login,
    '_state'            => $_state,
    'securable'         => $securable,
  }

  $login_permission_exists_parameters = {
    'login' => $login,
    '_state' => $_state,
    'with_grant_option' => $with_grant_option,
  }

  $query_login_permission_exists_parameters = {
    'permissions'                         => $permissions,
    'login_permission_exists_parameters'  => $login_permission_exists_parameters,
  }

  $_securable_tag = $securable ? {
    undef   => '',
    default => "-${securable}",
  }

  sqlserver_tsql { "login-permission-${instance}-${login}-${_state}${_grant_option}${_securable_tag}":
    instance => $instance,
    command  => epp('sqlserver/create/login/permission.sql.epp', $create_login_permission_parameters),
    onlyif   => epp('sqlserver/query/login/permission_exists.sql.epp', $query_login_permission_exists_parameters),
    require  => Sqlserver::Config[$instance],
  }
}
