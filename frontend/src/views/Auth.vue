<template>
	<div class="page-auth">
		<div v-if="!isLogged" class="wrapper flex justify-center">
			<div v-if="align === 'right'" class="image-box basis-2/3" />
			<div class="form-box flex basis-2/5 items-center justify-center" :class="{ centered: align === 'center' }">
				<AuthForm :type="type" />
			</div>
			<div v-if="align === 'left'" class="image-box basis-2/3">
				<PacmanGame />
			</div>
		</div>
	</div>
</template>

<script lang="ts" setup>
import type { FormType } from "@/components/auth/types.d"
import { computed, onBeforeMount, ref, toRefs } from "vue"
import { useRoute } from "vue-router"
import AuthForm from "@/components/auth/AuthForm.vue"
import PacmanGame from "@/components/auth/PacmanGame.vue"
import { useAuthStore } from "@/stores/auth"

type Align = "left" | "center" | "right"

const props = defineProps<{
	formType?: FormType
}>()
const { formType } = toRefs(props)

const route = useRoute()
const align = ref<Align>("left")
const type = ref<FormType | undefined>(formType.value || undefined)

const authStore = useAuthStore()
const isLogged = computed(() => authStore.isLogged)

onBeforeMount(() => {
	if (route.query.step) {
		const step = route.query.step as FormType
		type.value = step
	}
})
</script>

<style lang="scss" scoped>
.page-auth {
	min-height: 100svh;
	background: radial-gradient(circle at top left, rgba(30, 64, 175, 0.35), transparent 45%),
		radial-gradient(circle at bottom right, rgba(13, 148, 136, 0.28), transparent 42%), #020617;
	color: #e2e8f0;

	.wrapper {
		min-height: 100svh;
		background: linear-gradient(135deg, rgba(15, 23, 42, 0.55), rgba(2, 6, 23, 0.72));

		.image-box {
			position: relative;
			display: flex;
			align-items: center;
			justify-content: center;
			padding: 40px;
			background: transparent;
			overflow: hidden;
		}

		.form-box {
			padding: clamp(32px, 6vw, 64px);
			backdrop-filter: blur(12px);
			background: rgba(2, 6, 23, 0.7);
			box-shadow: 0 30px 60px rgba(2, 6, 23, 0.55);
			border-left: 1px solid rgba(148, 163, 184, 0.1);

			&.centered {
				flex-basis: 100%;

				.form-wrap {
					padding: clamp(32px, 8vw, 80px);
					width: 100%;
					max-width: 520px;
				}

				@media (max-width: 600px) {
					padding: 4%;
					.form-wrap {
						padding: 8%;
					}
				}
			}
		}
	}

	@media (max-width: 800px) {
		.wrapper {
			background: transparent;

			.image-box {
				display: none;
			}

			.form-box {
				flex-basis: 100%;
				padding: 32px;
				background: rgba(2, 6, 23, 0.8);
				border-left: none;
				border-top: 1px solid rgba(148, 163, 184, 0.1);
			}
		}
	}
}
</style>
