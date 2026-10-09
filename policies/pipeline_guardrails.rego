package pipeline

# Harness Governance policy. Attach it to a policy set on the "Pipeline" entity,
# "On Save", and these three rules block the save instead of waiting for review.

# Every step, including steps inside a parallel group.
all_steps[step] {
	step := input.pipeline.stages[_].stage.spec.execution.steps[_].step
}

all_steps[step] {
	step := input.pipeline.stages[_].stage.spec.execution.steps[_].parallel[_].step
}

# 1. No moving image tags.
deny[msg] {
	step := all_steps[_]
	image := step.spec.image
	not contains(image, "<+")
	not contains(image, "@sha256:")
	not has_tag(image)
	msg := sprintf("step '%s' uses image '%s' with no tag. Pin a version or a digest.", [step.identifier, image])
}

deny[msg] {
	step := all_steps[_]
	endswith(step.spec.image, ":latest")
	msg := sprintf("step '%s' uses the latest tag. Pin a version or a digest.", [step.identifier])
}

has_tag(image) {
	parts := split(image, "/")
	contains(parts[count(parts) - 1], ":")
}

# 2. Run steps need an explicit timeout.
deny[msg] {
	step := all_steps[_]
	step.type == "Run"
	not step.timeout
	msg := sprintf("step '%s' has no timeout.", [step.identifier])
}

# 3. A production deploy needs an Approval stage ahead of it.
deny[msg] {
	stage := input.pipeline.stages[i].stage
	stage.type == "Deployment"
	is_prod(stage.spec.environment.environmentRef)
	not approved_before(i)
	msg := sprintf("stage '%s' deploys to '%s' with no approval stage before it.", [stage.identifier, stage.spec.environment.environmentRef])
}

is_prod(ref) {
	lower(ref) == "prod"
}

is_prod(ref) {
	lower(ref) == "production"
}

approved_before(i) {
	input.pipeline.stages[j].stage.type == "Approval"
	j < i
}
