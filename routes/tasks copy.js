const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();
const tasksFile = path.join(__dirname, "../data/tasks.json");

// Ensure file exists
if (!fs.existsSync(tasksFile)) {
  fs.writeFileSync(tasksFile, JSON.stringify([]));
}

// Read tasks
const readTasks = () => {
  try {
    const data = fs.readFileSync(tasksFile, "utf-8");
    return JSON.parse(data || "[]");
  } catch (err) {
    console.error("Error reading tasks file:", err);
    return [];
  }
};

// Write tasks
const writeTasks = (tasks) => {
  fs.writeFileSync(tasksFile, JSON.stringify(tasks, null, 2));
};

// ✅ GET all tasks
router.get("/", (req, res) => {
  res.json(readTasks());
});

// ✅ GET one task
router.get("/:id", (req, res) => {
  const tasks = readTasks();
  const task = tasks.find((t) => t.taskId === req.params.id);
  if (!task) return res.status(404).json({ error: "Task not found" });
  res.json(task);
});

// ✅ POST create/update task
router.post("/", (req, res) => {
  const tasks = readTasks();
  const taskData = req.body;

  if (!taskData.taskId) {
    taskData.taskId = `T-${tasks.length + 1}`;
  }

  const existingIndex = tasks.findIndex((t) => t.taskId === taskData.taskId);
  const taskWithMeta = {
    ...taskData,
    createdAt: taskData.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    status: taskData.status || "Pending",
  };

  if (existingIndex >= 0) {
    tasks[existingIndex] = taskWithMeta;
  } else {
    tasks.push(taskWithMeta);
  }

  writeTasks(tasks);
  res.json(taskWithMeta);
});
// ✅ UPDATE task
router.put("/:id", (req, res) => {
  let tasks = readTasks();
  const index = tasks.findIndex((t) => t.taskId === req.params.id);

  if (index === -1) {
    return res.status(404).json({ error: "Task not found" });
  }

  const updatedTask = {
    ...tasks[index], // keep old fields
    ...req.body, // override with new data
    updatedAt: new Date().toISOString(),
  };

  tasks[index] = updatedTask;
  writeTasks(tasks);
  res.json(updatedTask);
});

// ✅ DELETE task
router.delete("/:id", (req, res) => {
  let tasks = readTasks();
  tasks = tasks.filter((t) => t.taskId !== req.params.id);
  writeTasks(tasks);
  res.json({ success: true });
});

module.exports = router;
