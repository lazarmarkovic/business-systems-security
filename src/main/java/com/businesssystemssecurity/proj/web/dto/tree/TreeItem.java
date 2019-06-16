package com.businesssystemssecurity.proj.web.dto.tree;


import java.util.ArrayList;

public class TreeItem {
    private long id;
    private String name;
    private ArrayList<TreeItem> children;

    public TreeItem() {
        this.children = new ArrayList<>();
    }

    public TreeItem(long id, String name, ArrayList<TreeItem> children) {
        this.id = id;
        this.name = name;
        this.children = children;
    }

    public TreeItem(long id, String name) {
        this.id = id;
        this.name = name;
        this.children = new ArrayList<>();
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public ArrayList<TreeItem> getChildren() {
        return children;
    }

    public void setChildren(ArrayList<TreeItem> children) {
        this.children = children;
    }
}
