---
"@glinr/theauth": minor
"@glinr/theauth-cli": minor
---

`theauth ros2 export` now adds the endpoints every ROS 2 node opens at start (`/rosout`, `/parameter_events` and the node's six parameter services). Without them a node under `ROS_SECURITY_STRATEGY=Enforce` fails at creation, which was observed on ros:humble with Fast DDS. Use `--node` and `--namespace` to name the node, or `--no-node-baseline` to leave them out. In the library, pass `nodeBaseline` to `exportRos2` (off by default there).
