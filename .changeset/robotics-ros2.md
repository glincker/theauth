---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
---

Add ROS 2 and robotics authorization.

`@glinr/theauth/robotics` is a new subpath. It maps theAuth permissions on `ros2:/topic`, `ros2:srv:/service` and `ros2:action:/action` resources (actions publish, subscribe, call, reply, execute) to the SROS2 policy format and to DDS Security 1.1 permissions and governance XML, the way SROS2's own `permissions.xsl` does. `exportRos2`, `buildRosPolicy`, `diffRosPolicies` and the XML writers are pure functions. Permissions that carry constraints DDS cannot enforce (approval, step up, rate, time window, IP, argument patterns) are left out of the static grant by default and reported as gated.

`guardRobotCommand` checks a command against `POST /authorize/token` and runs it only on an explicit allow. It fails closed on every error and lets an explicit, exact match list of safety stop resources through without a network call.

The CLI gains `theauth ros2 export` and `theauth ros2 diff`. Exported XML is unsigned. The docs page `robotics-ros2` has the signing commands, an rclpy gate node and an rclcpp sketch.
