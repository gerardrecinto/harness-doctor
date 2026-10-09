package pipeline

run_step(image, timeout) = {"step": s} {
	s := {"identifier": "r", "type": "Run", "timeout": timeout, "spec": {"image": image}}
}

ci(steps) = {"stage": {"identifier": "ci", "type": "CI", "spec": {"execution": {"steps": steps}}}}

deploy(env) = {"stage": {
	"identifier": "d",
	"type": "Deployment",
	"spec": {"environment": {"environmentRef": env}},
}}

approval = {"stage": {"identifier": "a", "type": "Approval", "spec": {}}}

test_pinned_image_passes {
	count(deny) == 0 with input as {"pipeline": {"stages": [ci([run_step("node:22.9", "5m")])]}}
}

test_digest_passes {
	count(deny) == 0 with input as {"pipeline": {"stages": [ci([run_step("node@sha256:abc", "5m")])]}}
}

test_untagged_image_denied {
	count(deny) == 1 with input as {"pipeline": {"stages": [ci([run_step("node", "5m")])]}}
}

test_latest_denied {
	count(deny) == 1 with input as {"pipeline": {"stages": [ci([run_step("node:latest", "5m")])]}}
}

test_parallel_steps_are_checked {
	count(deny) == 1 with input as {"pipeline": {"stages": [ci([{"parallel": [run_step("node:latest", "5m")]}])]}}
}

test_missing_timeout_denied {
	s := {"step": {"identifier": "r", "type": "Run", "spec": {}}}
	count(deny) == 1 with input as {"pipeline": {"stages": [ci([s])]}}
}

test_prod_without_approval_denied {
	count(deny) == 1 with input as {"pipeline": {"stages": [deploy("prod")]}}
}

test_prod_with_approval_passes {
	count(deny) == 0 with input as {"pipeline": {"stages": [approval, deploy("prod")]}}
}

test_staging_passes {
	count(deny) == 0 with input as {"pipeline": {"stages": [deploy("staging")]}}
}
