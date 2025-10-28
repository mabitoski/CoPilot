<template>
  <div ref="wrapperRef" class="pacman-game">
    <canvas ref="canvasRef" />
  </div>
</template>

<script lang="ts" setup>
import { onMounted, onUnmounted, reactive, ref } from "vue"

type Direction = { x: number; y: number }
type Virus = { x: number; y: number }
type Particle = { baseX: number; baseY: number; phase: number; speed: number; radius: number }

const wrapperRef = ref<HTMLDivElement | null>(null)
const canvasRef = ref<HTMLCanvasElement | null>(null)

const size = reactive({ width: 480, height: 320 })

const pacman = reactive({
  x: 0,
  y: 0,
  radius: 18,
  directionX: 1,
  directionY: 0,
})

const viruses = ref<Virus[]>([])
const particles = ref<Particle[]>([])
const baseSpeed = 160

let ctx: CanvasRenderingContext2D | null = null
let animationId = 0
let lastTimestamp = 0
let resizeObserver: ResizeObserver | null = null

function ensureContext(): CanvasRenderingContext2D | null {
  if (!canvasRef.value) return null
  if (!ctx) {
    ctx = canvasRef.value.getContext("2d")
  }
  return ctx
}

function createViruses(gridCols = 8, gridRows = 5): Virus[] {
  const created: Virus[] = []
  const paddingX = size.width * 0.12
  const paddingY = size.height * 0.18
  const stepX = (size.width - paddingX * 2) / (gridCols - 1)
  const stepY = (size.height - paddingY * 2) / (gridRows - 1)

  for (let row = 0; row < gridRows; row += 1) {
    for (let col = 0; col < gridCols; col += 1) {
      const jitterX = (Math.random() - 0.5) * stepX * 0.28
      const jitterY = (Math.random() - 0.5) * stepY * 0.28
      created.push({
        x: paddingX + col * stepX + jitterX,
        y: paddingY + row * stepY + jitterY,
      })
    }
  }
  return created
}

function createParticles(count = 18): Particle[] {
  return Array.from({ length: count }, () => ({
    baseX: Math.random(),
    baseY: Math.random(),
    phase: Math.random() * Math.PI * 2,
    speed: Math.random() * 0.00015 + 0.00005,
    radius: Math.random() * 0.6 + 0.4,
  }))
}

function updateCanvasSize() {
  const wrapper = wrapperRef.value
  const canvas = canvasRef.value
  if (!wrapper || !canvas) return

  const rect = wrapper.getBoundingClientRect()
  const ratio = window.devicePixelRatio || 1

  size.width = Math.max(320, rect.width)
  size.height = Math.max(260, rect.height)

  canvas.width = Math.floor(size.width * ratio)
  canvas.height = Math.floor(size.height * ratio)
  canvas.style.width = `${size.width}px`
  canvas.style.height = `${size.height}px`

  const context = ensureContext()
  if (!context) return
  context.setTransform(ratio, 0, 0, ratio, 0, 0)

  resetScene()
}

function resetScene() {
  pacman.x = size.width * 0.12
  pacman.y = size.height * 0.5
  pacman.directionX = 1
  pacman.directionY = 0
  lastTimestamp = 0
  viruses.value = createViruses()
  if (!particles.value.length) {
    particles.value = createParticles()
  }
}

function drawBackground(context: CanvasRenderingContext2D) {
  const gradient = context.createLinearGradient(0, 0, size.width, size.height)
  gradient.addColorStop(0, "#020617")
  gradient.addColorStop(1, "#0f172a")
  context.fillStyle = gradient
  context.fillRect(0, 0, size.width, size.height)

  context.strokeStyle = "rgba(56, 189, 248, 0.08)"
  context.lineWidth = 1
  const grid = 40
  for (let x = grid; x < size.width; x += grid) {
    context.beginPath()
    context.moveTo(x, 0)
    context.lineTo(x, size.height)
    context.stroke()
  }
  for (let y = grid; y < size.height; y += grid) {
    context.beginPath()
    context.moveTo(0, y)
    context.lineTo(size.width, y)
    context.stroke()
  }
}

function drawParticles(context: CanvasRenderingContext2D, delta: number) {
  context.save()
  context.globalCompositeOperation = "lighter"
  for (const particle of particles.value) {
    particle.phase += particle.speed * delta
    const offsetX = Math.cos(particle.phase) * 0.012
    const offsetY = Math.sin(particle.phase * 0.7) * 0.014
    const x = (particle.baseX + offsetX) * size.width
    const y = (particle.baseY + offsetY) * size.height
    const radius = particle.radius * 22
    const glow = context.createRadialGradient(x, y, 0, x, y, radius)
    glow.addColorStop(0, "rgba(56, 189, 248, 0.25)")
    glow.addColorStop(1, "rgba(56, 189, 248, 0)")
    context.fillStyle = glow
    context.beginPath()
    context.arc(x, y, radius, 0, Math.PI * 2)
    context.fill()
  }
  context.restore()
}

function drawViruses(context: CanvasRenderingContext2D) {
  viruses.value.forEach((virus, index) => {
    context.save()
    context.translate(virus.x, virus.y)
    const wiggle = Math.sin((lastTimestamp + index * 180) * 0.004)
    context.rotate(wiggle * 0.1)

    const bodyLength = 14
    const bodyWidth = 7
    const gradient = context.createLinearGradient(-bodyLength, 0, bodyLength, 0)
    gradient.addColorStop(0, "#0ea5e9")
    gradient.addColorStop(0.5, "#38bdf8")
    gradient.addColorStop(1, "#14b8a6")
    context.fillStyle = gradient
    context.shadowColor = "rgba(45, 212, 191, 0.35)"
    context.shadowBlur = 18
    context.beginPath()
    context.ellipse(0, 0, bodyLength, bodyWidth, 0, 0, Math.PI * 2)
    context.fill()
    context.shadowBlur = 0

    context.strokeStyle = "rgba(37, 211, 178, 0.6)"
    context.lineWidth = 1.4
    context.beginPath()
    context.moveTo(-bodyLength * 0.5, -bodyWidth * 0.8)
    context.lineTo(bodyLength * 0.5, -bodyWidth * 0.8)
    context.moveTo(-bodyLength * 0.5, 0)
    context.lineTo(bodyLength * 0.65, 0)
    context.moveTo(-bodyLength * 0.5, bodyWidth * 0.8)
    context.lineTo(bodyLength * 0.5, bodyWidth * 0.8)
    context.stroke()

    context.strokeStyle = "rgba(125, 211, 252, 0.7)"
    context.lineWidth = 1.6
    for (const side of [-1, 1] as const) {
      for (let i = 0; i < 3; i += 1) {
        const offset = -bodyLength * 0.2 + i * bodyLength * 0.4
        context.beginPath()
        context.moveTo(offset, side * bodyWidth * 0.8)
        context.quadraticCurveTo(
          offset - bodyLength * 0.25,
          side * bodyWidth * (1.2 + 0.2 * i),
          offset - bodyLength * 0.45,
          side * bodyWidth * (1.45 + 0.25 * i),
        )
        context.stroke()
      }
    }

    context.fillStyle = "#172554"
    context.beginPath()
    context.ellipse(bodyLength * 0.9, 0, bodyWidth * 0.8, bodyWidth * 0.7, 0, 0, Math.PI * 2)
    context.fill()
    context.strokeStyle = "rgba(56, 189, 248, 0.6)"
    context.lineWidth = 1.2
    context.beginPath()
    context.ellipse(bodyLength * 0.9, 0, bodyWidth * 0.8, bodyWidth * 0.7, 0, 0, Math.PI * 2)
    context.stroke()

    context.fillStyle = "#fef9c3"
    const eyeOffsetY = bodyWidth * 0.3
    const eyeOffsetX = bodyLength * 0.65
    context.beginPath()
    context.arc(eyeOffsetX, -eyeOffsetY, 1.8, 0, Math.PI * 2)
    context.arc(eyeOffsetX, eyeOffsetY, 1.8, 0, Math.PI * 2)
    context.fill()
    context.fillStyle = "#0f172a"
    context.beginPath()
    context.arc(eyeOffsetX + 0.6, -eyeOffsetY, 0.9, 0, Math.PI * 2)
    context.arc(eyeOffsetX + 0.6, eyeOffsetY, 0.9, 0, Math.PI * 2)
    context.fill()

    context.strokeStyle = "rgba(56, 189, 248, 0.7)"
    context.lineWidth = 1.2
    context.beginPath()
    context.moveTo(bodyLength * 0.9, -bodyWidth * 0.4)
    context.quadraticCurveTo(bodyLength * 1.2, -bodyWidth * 1.4, bodyLength * 0.7, -bodyWidth * 2)
    context.moveTo(bodyLength * 0.9, bodyWidth * 0.4)
    context.quadraticCurveTo(bodyLength * 1.2, bodyWidth * 1.4, bodyLength * 0.7, bodyWidth * 2)
    context.stroke()

    context.restore()
  })
}

function drawPacman(context: CanvasRenderingContext2D) {
  const mouthAngle = (Math.sin(lastTimestamp * 0.012) + 1) * 0.22 + 0.16
  const angle = Math.atan2(pacman.directionY, pacman.directionX)
  context.beginPath()
  context.fillStyle = "#fde047"
  context.shadowColor = "rgba(250, 224, 71, 0.45)"
  context.shadowBlur = 18
  context.arc(pacman.x, pacman.y, pacman.radius, angle + mouthAngle, angle - mouthAngle + Math.PI * 2, false)
  context.lineTo(pacman.x, pacman.y)
  context.fill()
  context.shadowBlur = 0

  context.beginPath()
  context.fillStyle = "#020617"
  context.arc(
    pacman.x + Math.cos(angle - Math.PI / 2) * 6,
    pacman.y + Math.sin(angle - Math.PI / 2) * 6,
    3,
    0,
    Math.PI * 2,
  )
  context.fill()
}

function updatePacman(delta: number) {
  if (!viruses.value.length) {
    viruses.value = createViruses()
  }
  const target = viruses.value.reduce((closest, virus) => {
    if (!closest) return virus
    const distCurrent = Math.hypot(virus.x - pacman.x, virus.y - pacman.y)
    const distClosest = Math.hypot(closest.x - pacman.x, closest.y - pacman.y)
    return distCurrent < distClosest ? virus : closest
  }, viruses.value[0])

  if (!target) return

  const dx = target.x - pacman.x
  const dy = target.y - pacman.y
  const distance = Math.hypot(dx, dy)
  if (distance > 1) {
    pacman.directionX = dx / distance
    pacman.directionY = dy / distance
    const travel = (baseSpeed * delta) / 1000
    if (travel >= distance) {
      pacman.x = target.x
      pacman.y = target.y
    } else {
      pacman.x += pacman.directionX * travel
      pacman.y += pacman.directionY * travel
    }
  }

  viruses.value = viruses.value.filter((virus) => Math.hypot(virus.x - pacman.x, virus.y - pacman.y) > 12)
}

function renderFrame(timestamp: number) {
  const context = ensureContext()
  if (!context) return
  if (!lastTimestamp) lastTimestamp = timestamp
  const delta = timestamp - lastTimestamp
  lastTimestamp = timestamp

  updatePacman(delta)
  context.clearRect(0, 0, size.width, size.height)
  drawBackground(context)
  drawParticles(context, delta)
  drawViruses(context)
  drawPacman(context)

  animationId = requestAnimationFrame(renderFrame)
}

function startGame() {
  if (animationId) return
  const context = ensureContext()
  if (!context) return
  context.clearRect(0, 0, size.width, size.height)
  drawBackground(context)
  drawParticles(context, 0)
  drawViruses(context)
  drawPacman(context)
  animationId = requestAnimationFrame(renderFrame)
}

function stopGame() {
  cancelAnimationFrame(animationId)
  animationId = 0
}

onMounted(() => {
  updateCanvasSize()
  resizeObserver = new ResizeObserver(() => updateCanvasSize())
  if (wrapperRef.value) {
    resizeObserver.observe(wrapperRef.value)
  }
  startGame()
})

onUnmounted(() => {
  stopGame()
  if (resizeObserver && wrapperRef.value) {
    resizeObserver.unobserve(wrapperRef.value)
  }
  resizeObserver = null
})
</script>

<style scoped>
.pacman-game {
  position: relative;
  display: flex;
  flex: 1 1 auto;
  width: 100%;
  height: 100%;
  align-items: stretch;
  justify-content: stretch;
  overflow: hidden;
  border-radius: 32px;
  box-shadow: inset 0 0 0 1px rgba(15, 118, 255, 0.15), 0 40px 60px rgba(8, 30, 66, 0.35);
  background: radial-gradient(circle at 20% 20%, rgba(56, 189, 248, 0.08), transparent 55%),
    radial-gradient(circle at 80% 80%, rgba(56, 248, 200, 0.08), transparent 50%), #020720;
}

canvas {
  display: block;
  width: 100%;
  height: 100%;
}
</style>
