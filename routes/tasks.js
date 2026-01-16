const express = require("express");
const Task = require("../models/Tasks");

const router = express.Router();

// ✅ Generate sequential Task ID (T-1, T-2, …)
const generateTaskId = async () => {
  const tasks = await Task.find({}, "taskId");
  if (tasks.length === 0) return "T-1";
  const lastNum = Math.max(
    ...tasks.map((t) => parseInt(t.taskId?.split("-")[1] || 0, 10))
  );
  return `T-${lastNum + 1}`;
};

// ✅ GET all tasks (with optional filters)
router.get("/", async (req, res) => {
  try {
    const { department, status } = req.query;
    const filter = {};
    if (department) filter.department = department;
    if (status) filter.status = status;

    const tasks = await Task.find(filter).sort({ createdAt: -1 });
    res.json(tasks);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ GET a single task by ID
router.get("/:id", async (req, res) => {
  try {
    const task = await Task.findOne({ taskId: req.params.id });
    if (!task) return res.status(404).json({ error: "Task not found" });
    res.json(task);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ POST create or update task
router.post("/", async (req, res) => {
  try {
    const taskData = req.body;

    if (!taskData.riskId || !taskData.department || !taskData.description) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    if (!taskData.taskId) {
      taskData.taskId = await generateTaskId();
    }

    let task = await Task.findOne({ taskId: taskData.taskId });

    if (task) {
      task = await Task.findOneAndUpdate(
        { taskId: taskData.taskId },
        { ...taskData },
        { new: true }
      );
    } else {
      task = new Task(taskData);
      await task.save();
    }

    res.json(task);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ PUT update existing task
router.put("/:id", async (req, res) => {
  try {
    const updatedTask = await Task.findOneAndUpdate(
      { taskId: req.params.id },
      { ...req.body },
      { new: true }
    );
    if (!updatedTask)
      return res.status(404).json({ error: "Task not found" });
    res.json(updatedTask);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ DELETE a task
router.delete("/:id", async (req, res) => {
  try {
    const deleted = await Task.findOneAndDelete({ taskId: req.params.id });
    if (!deleted) return res.status(404).json({ error: "Task not found" });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
